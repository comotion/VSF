
# For now
sub sec_useragent_sev1 {
    set req.http.X-VSF-Severity = "1";
    set req.http.X-VSF-Module = "useragent";
    call sec_handler;
}

sub vcl_recv {

    # Checks for php code in User-Agent
    if (req.http.user-agent ~ "php_uname\(") {
        set req.http.X-VSF-RuleName = "PHP Code in User-Agent: php_uname";
        set req.http.X-VSF-RuleID = "1";
        set req.http.X-VSF-RuleInfo = "Checks for php code in User-Agent: php_uname";
        call sec_useragent_sev1;
    }

    # Checks for php code in User-Agent
    if (req.http.user-agent ~ "curl_init\(") {
        set req.http.X-VSF-RuleName = "PHP Code in User-Agent: curl_init";
        set req.http.X-VSF-RuleID = "2";
        set req.http.X-VSF-RuleInfo = "Checks for php code in User-Agent: curl_init";
        call sec_useragent_sev1;
    }

    # Checks for php code in User-Agent
    if (req.http.user-agent ~ "curl_setopt\(") {
        set req.http.X-VSF-RuleName = "PHP Code in User-Agent: curl_setopt";
        set req.http.X-VSF-RuleID = "3";
        set req.http.X-VSF-RuleInfo = "Checks for php code in User-Agent: curl_setopt";
        call sec_useragent_sev1;
    }

    # Checks for php code in User-Agent
    if (req.http.user-agent ~ "curl_exec\(") {
        set req.http.X-VSF-RuleName = "PHP Code in User-Agent: curl_exec";
        set req.http.X-VSF-RuleID = "4";
        set req.http.X-VSF-RuleInfo = "Checks for php code in User-Agent: curl_exec";
        call sec_useragent_sev1;
    }

    # Checks for php code in User-Agent
    if (req.http.user-agent ~ "curl_close\(") {
        set req.http.X-VSF-RuleName = "PHP Code in User-Agent: curl_close";
        set req.http.X-VSF-RuleID = "5";
        set req.http.X-VSF-RuleInfo = "Checks for php code in User-Agent: curl_close";
        call sec_useragent_sev1;
    }

    # Checks for php code in User-Agent
    if (req.http.user-agent ~ "fopen\(") {
        set req.http.X-VSF-RuleName = "PHP Code in User-Agent: fopen";
        set req.http.X-VSF-RuleID = "6";
        set req.http.X-VSF-RuleInfo = "Checks for php code in User-Agent: fopen";
        call sec_useragent_sev1;
    }

    # Checks for php code in User-Agent
    if (req.http.user-agent ~ "fwrite\(") {
        set req.http.X-VSF-RuleName = "PHP Code in User-Agent: fwrite";
        set req.http.X-VSF-RuleID = "7";
        set req.http.X-VSF-RuleInfo = "Checks for php code in User-Agent: fwrite";
        call sec_useragent_sev1;
    }

    # Checks for bad User-Agent
    if (
     req.http.user-agent ~ "^$"
     || req.http.user-agent ~ "(?i)^java"
     || req.http.user-agent ~ "(?i)^python"
     || req.http.user-agent ~ "(?i)IDBot"
     || req.http.user-agent ~ "(?i)id-search"
     || req.http.user-agent ~ "(?i)^user-agent"
     || req.http.user-agent ~ "(?i)compatible ;"
     || req.http.user-agent ~ "(?i)^Mozilla$"
     || req.http.user-agent ~ "(?i)libwww"
     || req.http.user-agent ~ "(?i)lwp-trivial"
     || req.http.user-agent ~ "(?i)^curl"
     || req.http.user-agent ~ "(?i)PHP/"
     || req.http.user-agent ~ "(?i)urllib"
     || req.http.user-agent ~ "(?i)GT:WWW"
     || req.http.user-agent ~ "(?i)Snoopy"
     || req.http.user-agent ~ "(?i)MFC_Tear_Sample"
     || req.http.user-agent ~ "(?i)HTTP::Lite"
     || req.http.user-agent ~ "(?i)PHPCrawl"
     || req.http.user-agent ~ "(?i)URI::Fetch"
     || req.http.user-agent ~ "(?i)Zend_Http_Client"
     || req.http.user-agent ~ "(?i)http client"
     || req.http.user-agent ~ "(?i)PECL::HTTP"
     || req.http.user-agent ~ "(?i)htmlyse.com"
     || req.http.user-agent ~ "(?i)ecairn.com"
     || req.http.user-agent ~ "(?i)IBM EVV"
     || req.http.user-agent ~ "(?i)Bork-edition"
     || req.http.user-agent ~ "(?i)Fetch API Request"
     || req.http.user-agent ~ "(?i)PleaseCrawl"
     || req.http.user-agent ~ "[A-Z][a-z]{3,} [a-z]{4,} [a-z]{4,}"
     || req.http.user-agent ~ "(?i)layeredtech.com"
     || req.http.user-agent ~ "(?i)WEP Search"
     || req.http.user-agent ~ "(?i)JDatabaseDriverMysqli"
     || req.http.user-agent == "Guestbook Auto Submitter"
     || req.http.user-agent == "Industry Program 1.0.x"
     || req.http.user-agent == "IUPUI Research Bot v 1.9a"
     || req.http.user-agent == "LARBIN-EXPERIMENTAL (efp@gmx.net)"
     || req.http.user-agent == "LetsCrawl.com/1.0 +http://letscrawl.com/"
     || req.http.user-agent == "Lincoln State Web Browser"
     || req.http.user-agent == "LMQueueBot/0.2"
     || req.http.user-agent == "LWP::Simple/5.803"
     || req.http.user-agent == "Mac Finder 1.0.xx"
     || req.http.user-agent == "MFC Foundation Class Library 4.0"
     || req.http.user-agent == "Missauga Locate 1.0.0"
     || req.http.user-agent == "Missouri College Browse"
     || req.http.user-agent == "Mizzu Labs 2.2"
     || req.http.user-agent == "Mo College 1.9"
     || req.http.user-agent == "Mozilla/4.0 (compatible; Iplexx Spider/1.0 http://www.iplexx.at)"
     || req.http.user-agent == "Mozilla/4.0 efp@gmx.net"
     || req.http.user-agent == "Mozilla/5.0 (Version: xxxx Type:xx)"
     || req.http.user-agent == "MVAClient"
     || req.http.user-agent == "NASA Search 1.0"
     || req.http.user-agent == "Nsauditor/1.x"
     || req.http.user-agent == "PBrowse 1.4b"
     || req.http.user-agent == "PEval 1.4b"
     || req.http.user-agent == "Poirot"
     || req.http.user-agent == "Port Huron Labs"
     || req.http.user-agent == "ShablastBot 1.0"
     || req.http.user-agent == "snap.com beta crawler v0"
     || req.http.user-agent == "Snapbot/1.0"
     || req.http.user-agent == "Sogou Orion spider/3.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"
     || req.http.user-agent == "sogou spider"
     || req.http.user-agent == "Sogou web spider/3.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"
     || req.http.user-agent == "WebVulnCrawl.blogspot.com/1.0 libwww-perl/5.803"
     || req.http.user-agent == "WEP Search 00"
    ) {
        set req.http.X-VSF-RuleName = "Unwanted User-Agent";
        set req.http.X-VSF-RuleID = "100";
        set req.http.X-VSF-RuleInfo = "Checks if User-Agent is in banned list";
        call sec_useragent_sev1;
    }
    
	# Checks for bad User-Agent - From ModSecurity
	# - http://mod-security.svn.sourceforge.net/ (03_Global_Agents.conf)
	if (req.http.User-Agent ~ "(?i:(?:^(?:microsoft url|user-Agent|www\.weblogs\.com|(?:jakart|vi)a|(google|i{0,1}explorer{0,1}\.exe|(ms){0,1}ie( [0-9.]{1,}){0,1} {0,1}(compatible( browser){0,1}){0,1})$)|\bdatacha0s\b|; widows|\\\r|a(?: href=|d(?:sarobot|vanced email extractor)|gdm79@mail\.ru|miga-aweb\/3\.4|t(?:hens|tache|(?:omic_email_hunt|spid)er)|utoemailspider)|b(?:ackdoor|lack hole|utch__2\.1\.1|wh3_user_agent)|c(?:h(?:e(?:esebot|rrypicker)|ina(?: local browse 2\.|claw))|o(?:mpatible(?: ;(?: msie|\.)|-)|n(?:cealed defense|t(?:actbot\/|entsmartz)|veracrawler)|py(?:guard|rightcheck)|re-project\/1\.0)|rescent internet toolpak)|d(?:ig(?:imarc webreader|out4uagent)|ts agent)|e(?:ducate search vxb|mail(?:siphon|wolf|(?: extracto|reape)r|(siphon|spider)|(?:collec|harves|magne)t)|o browse|xtractorpro|(?:collecto|irgrabbe)r)|f(?:a(?:xobot|(?:ntombrows|stlwspid)er)|loodgate|oobar\/|ull web bot|(?:iddle|ranklin locato)r)|g(?:ameBoy, powered by nintendo|ecko\/25|rub(?: crawler|-client))|h(?:anzoweb|hjhj@yahoo|l_ftien_spider)|i(?:n(?:dy library|ternet(?: (?:exploiter sux|ninja)|-exprorer))|sc systems irc search 2\.1)|kenjin spider|larbin@unspecified|m(?:ailto:craftbot@yahoo\.com|i(?:crosoft (?:internet explorer\/5\.0$|url control)|ssigua)|o(?:r(?:feus fucking scanner|zilla)|siac 1.|zilla\/3\.mozilla\/2\.01$)|urzillo compatible)|n(?:ameofagent|e(?:ssus|(?:uralbot\/0\.|wt activeX; win3)2)|ikto|o(?: browser|kia-waptoolkit.{0,} googlebot.{0,}googlebot))|p(?:a(?:ckrat|nscient\.com)|cbrowser|e 1\.4|leasecrawl\/1\.|mafind|oe-component-client|ro(?:duction bot|gram shareware 1\.0\.|webwalker)|s(?:urf|ycheclone))|rsync|s(?:\.t\.a\.l\.k\.e\.r\.|afexplorer tl|e(?:archbot admin@google.com|curity scan)|hai|itesnagger|(?:tress tes|urveybo)t)|t(?:ele(?:port pro|soft)|oata dragostea mea pentru diavola|uring machine|(?: {0,1}h {0,1}a {0,1}t {0,1}' {0,1}s g {0,1}o {0,1}t {0,1}t {0,1}a {0,1} h {0,1}u {0,1}r {0,1}|akeou|his is an exploi)t)|u(?:nder the rainbow 2\.|ser-agent:)|v(?:adixbot|oideye)|w(?:3mir|e(?:b(?: (?:by mail|downloader)|emailextract{0,1}|mole|vulnscan|(?:bandi|(?:altb|ro)o)t)|lls search ii|p Search 00)|i(?:ndows(?:-update-agent)|se(?:nut){0,1}bot)|ordpress(?: hash grabber|\/4\.01))|zeus(?: .{0,}webster pro){0,1}|[a-z]surf[0-9][0-9]|(?:$botname\/$botvers|(script|sql) inject)ion|(compatible ; msie|msie .{1,}; .{0,}windows xp)|(?:8484 boston projec|xmlrpc exploi)t|(sogou develop spider|sohu agent)|(?:demo bot|(?:d|e)browse)|(libwen-us|myie2|murzillo compatible|webaltbot|wisenutbot)))") {
        set req.http.X-VSF-RuleName = "Unwanted User-Agent";
        set req.http.X-VSF-RuleID = "101";
        set req.http.X-VSF-RuleInfo = "Checks if User-Agent is in banned list";
        call sec_useragent_sev1;
	}
}
