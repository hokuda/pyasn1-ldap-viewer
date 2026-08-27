# LDAP Hex Dump Decoder

Java の `-Djavax.net.debug=ssl,record,plaintext` 出力に含まれる、復号後の
plaintext hex ダンプ部分（`Plaintext before ENCRYPTION (` / `Plaintext after
DECRYPTION (` に続くブロック）を貼り付けると、
[pyasn1_ldap](https://github.com/hokuda/pyasn1_ldap) を使って LDAP メッセージ
としてデコードし、人が読める形式（`prettyPrint()` のツリー表示）で表示します。

すべての処理は [Pyodide](https://pyodide.org/)（WebAssembly 上で動く
CPython）でブラウザ内で完結します。サーバー側の処理は一切なく、GitHub Pages
のような静的ホスティングだけで動作します。

## 使い方

1. Java 側のログから hex ダンプ部分（オフセット・16進バイト列・ASCII サイド
   バーの行）だけをコピーします。前後の `Plaintext before ENCRYPTION (` /
   `)` の行が混ざっていても問題ありません。
2. テキストエリアに貼り付けて「Decode」ボタンを押します。
3. 1つの貼り付けに複数の LDAPMessage が連結して含まれている場合は、
   それぞれ "Message 1", "Message 2", ... として表示されます。

## ローカルでの動作確認

`file://` で `index.html` を直接開くと `fetch()` / `loadPyodide()` が失敗する
ため、簡易 HTTP サーバー経由で開いてください。

```sh
python3 -m http.server 8000
```

ブラウザで `http://localhost:8000/` を開き、ステータス表示が
「Loading Python runtime…」→「Loading micropip…」→
「Installing pyasn1_ldap from PyPI…」→「Ready.」と進み、Decode ボタンが
有効になることを確認します。

## GitHub Pages へのデプロイ

このリポジトリはビルド不要の静的ファイルのみで構成されています。

1. `main` ブランチに push する。
2. リポジトリの Settings → Pages → Source を
   "Deploy from a branch" / Branch: `main` / `(root)` に設定する。
3. 発行された URL でページが開けることを確認する。

## 制限事項

- `pyasn1_ldap` は PyPI 上の単一リリース（0.1.0）の小規模なパッケージです。
  実行時に PyPI から直接取得するため、PyPI への接続がブロックされている環境
  （社内プロキシ等）では動作しません。
- 初回ロードは Pyodide 本体と依存パッケージのダウンロードのため数秒〜十数秒
  かかります。
