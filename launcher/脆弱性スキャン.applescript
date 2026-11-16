-- 脆弱性スキャン: DefectDojo とキットの画面を起動して、ブラウザで開く(security-scan-kit)
-- 作り直すとき: osacompile -o ~/Desktop/脆弱性スキャン.app launcher/脆弱性スキャン.applescript
on run
	set kit to (POSIX path of (path to home folder)) & "work/security-scan-kit"
	try
		display notification "起動しています(初回は数分かかります)" with title "脆弱性スキャン"
		do shell script quoted form of (kit & "/bin/kit") & " up --open >> " & quoted form of (kit & "/data/launcher.log") & " 2>&1"
	on error errMsg
		display dialog "起動できませんでした。" & return & return & "ログ: " & kit & "/data/launcher.log" & return & errMsg buttons {"OK"} default button "OK" with icon caution with title "脆弱性スキャン"
	end try
end run
