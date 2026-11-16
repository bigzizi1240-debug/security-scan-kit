# 同梱SASTルール

このルール集は既存のAI脆弱性診断ワークスペースから取り込んだMITルールです。
Semgrep社の制限付きルール集や、検査対象リポジトリの設定ファイルは利用しません。

- upstream: elttam/semgrep-rules、commit `244268562cc92d33f54b8a60a187df5520f91b26`。
- `manifest.json`は原本と同一で、ファイルごとのSHA-256とルールIDを保持します。
- `local-*.yaml`はAI Vuln Lab contributorsによるMITルールです。
- `catalog.json`は同梱YAMLの固定メッセージから生成した表示用の説明です。検出ソースを含みません。
- scanner設定にmanifestとcatalogのhashを固定し、全ルールの一致を検査前に確認します。

検出結果は手動確認の候補です。入力の到達・実行・悪用の成立や全言語の網羅性は保証しません。
検査対象のインストール・ビルドスクリプトは実行しません。

## ローカルルールのMITライセンス

Copyright (c) 2026 AI Vuln Lab contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
