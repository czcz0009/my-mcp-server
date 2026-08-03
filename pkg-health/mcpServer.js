/**
 * pkg-health-actor MCP サーバー
 *
 * checkPackageHealth.js の既存関数を、そのまま MCP Tool としてラップする。
 * Tool定義:
 *   - check_package_health: パッケージの健全性(メンテ状況など)+ 最新バージョンの脆弱性を返す
 *   - check_vulnerabilities: 指定パッケージ(任意でバージョン指定)の既知脆弱性を返す
 *   - check_dependency_tree_risk: package-lock.json 全体をスキャンし、依存ツリー内の
 *     既知脆弱性リスクをサマリ+上位N件の詳細として返す(check_vulnerabilities で
 *     指摘されていた間接依存の脆弱性を拾うためのTool)
 *
 * 既知の課題(Phase 1 では未対応):
 *   check_package_health / check_vulnerabilities は対象パッケージ単体しか見ないため
 *   間接依存(transitive dependency)の脆弱性は拾えない(event-stream 事件のケース)。
 *   check_dependency_tree_risk はこれに対応するために追加したが、大規模lockfile対策として
 *   スキャン対象は先頭100パッケージまで、詳細を返すのはMedium以上の上位20件までに絞っている。
 *
 * 起動方法: node mcpServer.js
 * (MCPクライアントから stdio 経由で起動されることを想定)
 *
 * Apify Actor(pay-per-event)課金:
 *   このファイルは Apify Actor (my-mcp-server) にラップされて動く際、
 *   .actor/pay_per_event.json で定義した3イベント(check-package-health /
 *   check-vulnerabilities / check-dependency-tree)に対応する Actor.charge() を、
 *   各Toolの処理が成功した直後に呼び出す。Actor.charge() は pay-per-event が
 *   未設定、または Apify platform外(スタンドアロン実行)では警告ログのみで
 *   no-opになる(SDK側の挙動)ため、Claude Desktop等からの直接起動でも安全。
 */

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');
const { Actor } = require('apify');

const { checkPackageHealth, checkVulnerabilities, checkDependencyTreeRisk } = require('./checkPackageHealth');

const server = new McpServer({
  name: 'pkg-health-actor',
  version: '1.0.0',
});

server.registerTool(
  'check_package_health',
  {
    title: 'npm パッケージの健全性チェック',
    description:
      'npm registry の情報から、指定パッケージの健全性(最終更新からの経過日数、メンテナ数、バージョン公開頻度など)を判定し、' +
      '合わせて最新バージョンの既知脆弱性(OSV.dev)も取得する。間接依存の脆弱性は対象外。',
    inputSchema: {
      packageName: z.string().describe('npm パッケージ名 (例: "minimist")'),
    },
  },
  async ({ packageName }) => {
    try {
      const result = await checkPackageHealth(packageName);
      await Actor.charge({ eventName: 'check-package-health' });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    } catch (err) {
      return {
        content: [{ type: 'text', text: `エラー: ${err.message}` }],
        isError: true,
      };
    }
  }
);

server.registerTool(
  'check_vulnerabilities',
  {
    title: 'npm パッケージの既知脆弱性チェック',
    description:
      'OSV.dev と GitHub Security Advisories (GHSA) の両方に問い合わせて、指定パッケージ' +
      '(バージョン指定があればそのバージョンに影響するもの、未指定なら全バージョン対象)の' +
      '既知脆弱性を取得する。同一脆弱性はCVE ID等で重複排除され、各結果の"source"に' +
      '"osv"|"ghsa"|"both"のいずれかが入る。間接依存の脆弱性は対象外。',
    inputSchema: {
      packageName: z.string().describe('npm パッケージ名 (例: "minimist")'),
      version: z.string().optional().describe('対象バージョン(省略時は全バージョンを対象に検索)'),
      ecosystem: z
        .string()
        .optional()
        .default('npm')
        .describe('OSV.dev のエコシステム名(既定: "npm")'),
    },
  },
  async ({ packageName, version, ecosystem }) => {
    try {
      const result = await checkVulnerabilities(packageName, version, ecosystem);
      await Actor.charge({ eventName: 'check-vulnerabilities' });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    } catch (err) {
      return {
        content: [{ type: 'text', text: `エラー: ${err.message}` }],
        isError: true,
      };
    }
  }
);

server.registerTool(
  'check_dependency_tree_risk',
  {
    title: 'package-lock.json の依存ツリー脆弱性リスクチェック',
    description:
      'package-lock.json の中身(文字列)を受け取り、依存ツリー全体(lockfileVersion 1/2/3に対応)から' +
      '{name, version} を抽出してOSV.devのバッチAPIでまとめて問い合わせる。間接依存の脆弱性もカバーする。' +
      '大規模lockfile対策として、スキャン対象は先頭100パッケージまで、詳細を返すのはMedium以上の深刻度・上位20件までに絞っている。' +
      '出力は全体サマリ(スキャン件数・ヒット数・深刻度別内訳)と上位N件の詳細のみで、生の全件は返さない。',
    inputSchema: {
      lockfileContent: z.string().describe('package-lock.json ファイルの中身(JSON文字列)'),
      ecosystem: z
        .string()
        .optional()
        .default('npm')
        .describe('OSV.dev のエコシステム名(既定: "npm")'),
    },
  },
  async ({ lockfileContent, ecosystem }) => {
    try {
      const result = await checkDependencyTreeRisk(lockfileContent, ecosystem);
      await Actor.charge({ eventName: 'check-dependency-tree' });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    } catch (err) {
      return {
        content: [{ type: 'text', text: `エラー: ${err.message}` }],
        isError: true,
      };
    }
  }
);

async function main() {
  try {
    // gracefulShutdown: false - このプロセスは親(Actorのmain.ts)から起動される
    // 子プロセスであり、aborting/migrating時のActor.exit()/reboot()はActor全体の
    // ライフサイクルを持つ親側の責務。ここでは pay-per-event の課金設定を読み込むために
    // init() するだけで、Actor.charge() が正しく platform 上の価格情報を参照できるようにする。
    await Actor.init({ gracefulShutdown: false });
  } catch (err) {
    console.error('Actor.init() に失敗しました(課金は無効化されます):', err.message);
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('pkg-health-actor MCP server running on stdio');
}

main().catch(err => {
  console.error('MCPサーバーの起動に失敗しました:', err);
  process.exit(1);
});
