/**
 * check_package_health
 * npm registry の情報から、パッケージの「健全性」を判定するための
 * 生データを取得・整形する最小プロトタイプ。
 *
 * 使い方: node checkPackageHealth.js <package-name>
 */

async function fetchPackageMetadata(packageName) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
  const res = await fetch(url);

  if (res.status === 404) {
    throw new Error(`パッケージ "${packageName}" は見つかりませんでした`);
  }
  if (!res.ok) {
    throw new Error(`registry.npmjs.org への問い合わせに失敗しました (status: ${res.status})`);
  }

  return res.json();
}

function analyzeHealth(meta) {
  const latestVersion = meta['dist-tags']?.latest;
  const latestVersionTime = meta.time?.[latestVersion];
  const createdTime = meta.time?.created;

  const now = new Date();
  const daysSinceLastPublish = latestVersionTime
    ? Math.floor((now - new Date(latestVersionTime)) / (1000 * 60 * 60 * 24))
    : null;

  // メンテナ数(推定): maintainers フィールドの人数
  const maintainerCount = Array.isArray(meta.maintainers) ? meta.maintainers.length : 0;

  // バージョン公開頻度(推定): 全バージョン数 / パッケージの存在期間(年)
  const versionCount = meta.time ? Object.keys(meta.time).filter(k => k !== 'created' && k !== 'modified').length : 0;
  const ageYears = createdTime
    ? (now - new Date(createdTime)) / (1000 * 60 * 60 * 24 * 365)
    : null;
  const releasesPerYear = ageYears && ageYears > 0 ? +(versionCount / ageYears).toFixed(2) : null;

  // 簡易リスクフラグ判定(あくまで一次プロトタイプの粗い基準)
  const flags = [];
  if (daysSinceLastPublish !== null && daysSinceLastPublish > 730) {
    flags.push('2年以上更新なし(メンテ放棄の可能性)');
  } else if (daysSinceLastPublish !== null && daysSinceLastPublish > 365) {
    flags.push('1年以上更新なし(要注意)');
  }
  if (maintainerCount === 1) {
    flags.push('メンテナが1人のみ(バス係数リスク)');
  }
  if (maintainerCount === 0) {
    flags.push('メンテナ情報が取得できず');
  }

  return {
    name: meta.name,
    latestVersion,
    lastPublishDate: latestVersionTime || null,
    daysSinceLastPublish,
    maintainerCount,
    versionCount,
    releasesPerYear,
    license: meta.license || meta.versions?.[latestVersion]?.license || '不明',
    repository: meta.repository?.url || null,
    flags,
  };
}

/**
 * OSV.dev に既知の脆弱性を問い合わせる。
 * version を指定すると「そのバージョンに影響する脆弱性」に絞られる。
 * version を省略すると「このパッケージ全体で過去報告された脆弱性」を返す。
 */
async function fetchVulnerabilities(packageName, version, ecosystem = 'npm') {
  const url = 'https://api.osv.dev/v1/query';

  const body = {
    package: {
      name: packageName,
      ecosystem,
    },
  };
  if (version) {
    body.version = version;
  }

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    throw new Error(`OSV.dev への問い合わせに失敗しました (status: ${res.status})`);
  }

  const data = await res.json();
  return data.vulns || [];
}

/**
 * OSV.dev のレコードは情報量が多いので、
 * エージェントが読みやすい最小限の形に整形する。
 */
function summarizeVulnerabilities(vulns) {
  return vulns.map(v => {
    // severity は CVSS 文字列で入っていることが多い。
    // 例: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    // これは数値スコアではなく「ベクトル文字列」なので、
    // 先頭の "3.1" はCVSSのバージョン番号であり深刻度ではない。
    // (これを深刻度スコアと誤読するバグが以前あった)
    const severityEntry = v.severity?.[0];
    const cvssVector = severityEntry?.score || null;

    // C(機密性)/I(完全性)/A(可用性) の影響度から簡易的に深刻度を推定する。
    // 正式なCVSS計算式ではなく、あくまで簡易プロトタイプの近似ロジック。
    let severityLevel = '不明';
    if (cvssVector) {
      const impacts = ['C', 'I', 'A'].map(key => {
        const m = cvssVector.match(new RegExp(`/${key}:([A-Z])`));
        return m ? m[1] : null;
      });
      const highCount = impacts.filter(i => i === 'H').length;
      const lowCount = impacts.filter(i => i === 'L').length;
      const acHigh = /\/AC:H/.test(cvssVector);
      const uiRequired = /\/UI:R/.test(cvssVector);

      if (highCount >= 2 && !acHigh && !uiRequired) {
        severityLevel = 'Critical';
      } else if (highCount >= 1) {
        severityLevel = 'High';
      } else if (lowCount >= 1) {
        severityLevel = 'Medium';
      } else {
        severityLevel = 'Low';
      }
    }

    return {
      id: v.id,
      summary: v.summary || v.details?.slice(0, 200) || '詳細なし',
      severityLevel,
      cvssVector,
      publishedDate: v.published || null,
      affectedRanges: v.affected?.map(a => a.ranges).flat() || [],
      references: (v.references || []).map(r => r.url).slice(0, 3),
    };
  });
}

async function checkVulnerabilities(packageName, version, ecosystem = 'npm') {
  const rawVulns = await fetchVulnerabilities(packageName, version, ecosystem);
  const summarized = summarizeVulnerabilities(rawVulns);

  const criticalOrHigh = summarized.filter(
    v => v.severityLevel === 'Critical' || v.severityLevel === 'High'
  );

  return {
    packageName,
    version: version || '(全バージョン対象)',
    ecosystem,
    totalVulnerabilities: summarized.length,
    criticalOrHighCount: criticalOrHigh.length,
    vulnerabilities: summarized,
  };
}

// ---- check_dependency_tree_risk 関連 ----

const DEPTREE_MAX_PACKAGES = 100; // 大規模lockfile対策: 先頭100パッケージまで
const DEPTREE_MAX_DETAIL_FETCHES = 150; // 個別詳細取得(GET /v1/vulns/{id})の上限
const DEPTREE_TOP_N_DETAILS = 20; // 詳細を返す上位件数
const DEPTREE_MIN_SEVERITY = 'Medium'; // これ未満(Low/不明)は詳細から除外
const SEVERITY_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, '不明': 0 };

/**
 * package-lock.json の中身(文字列)から {name, version} のペアを抽出する。
 * lockfileVersion 1 と 2/3 で構造が異なるため、それぞれに対応する:
 *   - v2/v3: "packages" フィールドを優先的にパースする
 *     (キーは "node_modules/foo" や "node_modules/@scope/bar" 形式)
 *   - v1: "dependencies" フィールドを再帰的に辿る
 *     (transitive依存は各パッケージの入れ子の "dependencies" に現れる)
 * 同名・同バージョンの重複は除去する。
 */
function extractPackagesFromLockfile(lockfileContent) {
  let lock;
  try {
    lock = JSON.parse(lockfileContent);
  } catch (err) {
    throw new Error(`package-lock.json のパースに失敗しました: ${err.message}`);
  }

  const lockfileVersion = lock.lockfileVersion || 1;
  const pairs = [];
  const seen = new Set();

  const addPair = (name, version) => {
    if (!name || !version) return;
    const key = `${name}@${version}`;
    if (seen.has(key)) return;
    seen.add(key);
    pairs.push({ name, version });
  };

  if (lock.packages && typeof lock.packages === 'object') {
    // v2/v3: packages フィールドを優先
    for (const [pkgPath, pkgInfo] of Object.entries(lock.packages)) {
      if (pkgPath === '' || !pkgInfo || pkgInfo.link) continue; // ルート自身・workspaceリンクは対象外
      const idx = pkgPath.lastIndexOf('node_modules/');
      if (idx === -1) continue;
      const name = pkgPath.slice(idx + 'node_modules/'.length);
      addPair(name, pkgInfo.version);
    }
  } else if (lock.dependencies && typeof lock.dependencies === 'object') {
    // v1: dependencies を再帰的に辿る(入れ子が transitive依存の別バージョン)
    const walk = deps => {
      for (const [name, info] of Object.entries(deps)) {
        if (!info) continue;
        addPair(name, info.version);
        if (info.dependencies && typeof info.dependencies === 'object') {
          walk(info.dependencies);
        }
      }
    };
    walk(lock.dependencies);
  }

  return { lockfileVersion, pairs };
}

/**
 * OSV.dev のバッチAPI (POST /v1/querybatch) に {name, version} のペアをまとめて問い合わせる。
 * レスポンスは脆弱性IDのみ({id, modified})で詳細は含まれない。
 * 1リクエストあたり最大1000件までのため、超える場合は分割して送る。
 */
async function queryOsvBatch(pairs, ecosystem = 'npm') {
  const OSV_BATCH_ENDPOINT = 'https://api.osv.dev/v1/querybatch';
  const CHUNK_SIZE = 1000;
  const results = [];

  for (let i = 0; i < pairs.length; i += CHUNK_SIZE) {
    const chunk = pairs.slice(i, i + CHUNK_SIZE);
    const body = {
      queries: chunk.map(p => ({
        package: { name: p.name, ecosystem },
        version: p.version,
      })),
    };

    const res = await fetch(OSV_BATCH_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      throw new Error(`OSV.dev バッチ問い合わせに失敗しました (status: ${res.status})`);
    }

    const data = await res.json();
    results.push(...(data.results || []));
  }

  return results; // pairs と同じ順序で { vulns?: [{id, modified}, ...] } が並ぶ
}

/**
 * 脆弱性IDのリストから、GET /v1/vulns/{id} で詳細を個別取得する。
 * 全件詳細化は行わず、呼び出し側で件数を絞ってから渡す前提。
 * 並列数を制限しつつ取得し、失敗したIDはスキップする。
 */
async function fetchVulnDetailsByIds(ids, concurrency = 10) {
  const OSV_VULN_ENDPOINT = 'https://api.osv.dev/v1/vulns';
  const results = new Array(ids.length).fill(null);
  let cursor = 0;

  async function worker() {
    while (cursor < ids.length) {
      const current = cursor++;
      const id = ids[current];
      try {
        const res = await fetch(`${OSV_VULN_ENDPOINT}/${encodeURIComponent(id)}`);
        if (res.ok) {
          results[current] = await res.json();
        }
      } catch {
        // 個別取得の失敗はスキップ(他のIDの取得は継続する)
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, ids.length) }, worker);
  await Promise.all(workers);

  return results.filter(Boolean);
}

/**
 * package-lock.json 全体の依存ツリーをスキャンし、既知脆弱性のリスクをまとめる。
 *
 * 処理の流れ:
 *   1. lockfile から {name, version} を抽出(上位 DEPTREE_MAX_PACKAGES 件まで)
 *   2. OSV.dev バッチAPIでまとめて問い合わせ、ヒットしたIDだけを集める
 *   3. ユニークなIDのうち上位 DEPTREE_MAX_DETAIL_FETCHES 件だけ個別に詳細取得
 *   4. 既存の summarizeVulnerabilities() で深刻度判定(CVSSベクトル解析ロジックを再利用)
 *   5. Medium以上のみ、深刻度上位 DEPTREE_TOP_N_DETAILS 件を詳細として返す
 *
 * 戻り値は「全体サマリ」+「上位N件の詳細」のみで、生の全件は返さない。
 */
async function checkDependencyTreeRisk(lockfileContent, ecosystem = 'npm') {
  const { lockfileVersion, pairs } = extractPackagesFromLockfile(lockfileContent);

  const totalPackagesFound = pairs.length;
  const scanned = pairs.slice(0, DEPTREE_MAX_PACKAGES);
  const packagesTruncated = totalPackagesFound > DEPTREE_MAX_PACKAGES;

  const emptySeverityBreakdown = { Critical: 0, High: 0, Medium: 0, Low: 0, '不明': 0 };

  if (scanned.length === 0) {
    return {
      lockfileVersion,
      ecosystem,
      totalPackagesFound: 0,
      scannedPackageCount: 0,
      packagesTruncated: false,
      packagesWithVulnerabilities: 0,
      uniqueVulnerabilityCount: 0,
      detailsFetchedCount: 0,
      detailsTruncated: false,
      severityBreakdown: emptySeverityBreakdown,
      topDetails: [],
      note: 'lockfile からパッケージを抽出できませんでした',
    };
  }

  const batchResults = await queryOsvBatch(scanned, ecosystem);

  const idToPackages = new Map(); // id -> Set("name@version")
  let packagesWithVulnerabilities = 0;

  scanned.forEach((pkg, idx) => {
    const vulns = batchResults[idx]?.vulns || [];
    if (vulns.length === 0) return;
    packagesWithVulnerabilities++;
    for (const v of vulns) {
      if (!idToPackages.has(v.id)) idToPackages.set(v.id, new Set());
      idToPackages.get(v.id).add(`${pkg.name}@${pkg.version}`);
    }
  });

  const uniqueIds = Array.from(idToPackages.keys());

  if (uniqueIds.length === 0) {
    return {
      lockfileVersion,
      ecosystem,
      totalPackagesFound,
      scannedPackageCount: scanned.length,
      packagesTruncated,
      packagesWithVulnerabilities: 0,
      uniqueVulnerabilityCount: 0,
      detailsFetchedCount: 0,
      detailsTruncated: false,
      severityBreakdown: emptySeverityBreakdown,
      topDetails: [],
    };
  }

  const idsToFetch = uniqueIds.slice(0, DEPTREE_MAX_DETAIL_FETCHES);
  const detailsTruncated = uniqueIds.length > DEPTREE_MAX_DETAIL_FETCHES;

  const rawDetails = await fetchVulnDetailsByIds(idsToFetch);
  // 深刻度判定は既存ロジック(summarizeVulnerabilities)をそのまま再利用する
  const summarized = summarizeVulnerabilities(rawDetails);

  const severityBreakdown = { ...emptySeverityBreakdown };
  const enriched = summarized.map(v => {
    severityBreakdown[v.severityLevel] = (severityBreakdown[v.severityLevel] || 0) + 1;
    return {
      ...v,
      affectedPackages: Array.from(idToPackages.get(v.id) || []),
    };
  });

  const topDetails = enriched
    .filter(v => SEVERITY_RANK[v.severityLevel] >= SEVERITY_RANK[DEPTREE_MIN_SEVERITY])
    .sort((a, b) => SEVERITY_RANK[b.severityLevel] - SEVERITY_RANK[a.severityLevel])
    .slice(0, DEPTREE_TOP_N_DETAILS);

  return {
    lockfileVersion,
    ecosystem,
    totalPackagesFound,
    scannedPackageCount: scanned.length,
    packagesTruncated,
    packagesWithVulnerabilities,
    uniqueVulnerabilityCount: uniqueIds.length,
    detailsFetchedCount: idsToFetch.length,
    detailsTruncated,
    severityBreakdown,
    topDetails,
  };
}

async function checkPackageHealth(packageName) {
  const meta = await fetchPackageMetadata(packageName);
  const health = analyzeHealth(meta);

  // health チェックのついでに、最新バージョンの脆弱性も合わせて取得する
  let vulnSummary;
  try {
    vulnSummary = await checkVulnerabilities(packageName, health.latestVersion);
  } catch (err) {
    vulnSummary = { error: `脆弱性情報の取得に失敗しました: ${err.message}` };
  }

  return {
    ...health,
    vulnerabilities: vulnSummary,
  };
}

// CLI実行用
if (require.main === module) {
  const packageName = process.argv[2];
  const mode = process.argv[3]; // 'health' | 'vuln' | 未指定なら両方
  const versionOverride = process.argv[4]; // 'vuln' モード時に任意のバージョンを指定可能

  if (!packageName) {
    console.error('使い方: node checkPackageHealth.js <package-name> [health|vuln] [version]');
    console.error('例: node checkPackageHealth.js minimist vuln 1.2.5');
    console.error('lockfileスキャン: node checkPackageHealth.js <package-lock.jsonのパス> deptree');
    process.exit(1);
  }

  const run = async () => {
    if (mode === 'deptree') {
      const fs = require('fs');
      const lockfileContent = fs.readFileSync(packageName, 'utf8'); // このモードでは第1引数をファイルパスとして扱う
      return checkDependencyTreeRisk(lockfileContent);
    }
    if (mode === 'vuln') {
      let targetVersion = versionOverride;
      if (!targetVersion) {
        const meta = await fetchPackageMetadata(packageName);
        targetVersion = meta['dist-tags']?.latest;
      }
      return checkVulnerabilities(packageName, targetVersion);
    }
    if (mode === 'health') {
      const meta = await fetchPackageMetadata(packageName);
      return analyzeHealth(meta);
    }
    return checkPackageHealth(packageName);
  };

  run()
    .then(result => console.log(JSON.stringify(result, null, 2)))
    .catch(err => {
      console.error('エラー:', err.message);
      process.exit(1);
    });
}

module.exports = {
  checkPackageHealth,
  fetchPackageMetadata,
  analyzeHealth,
  fetchVulnerabilities,
  summarizeVulnerabilities,
  checkVulnerabilities,
  checkDependencyTreeRisk,
  extractPackagesFromLockfile,
};
