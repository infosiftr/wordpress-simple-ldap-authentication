Þ    )      d  ;   ¬        P     ~   ê  /   i  F     t   à  g   U  t   ½  3   2  Q   f     ¸  .   À     ï  ;   ÷     3     A     V     m  `     7   â  
        %  0   1  >   b  ~   ¡      	  Q  ¦	     ø  $   	     .     7     E     \  ø  z     s  "        ±     Ï     å     ô          )     ¹      9  =   Ú  y          ¥   -     Ó  7   ^  e        ü  j   	  <   t  ¥   ±  `   W  &   ¸     ß  -   þ     ,  F   °     ÷     	  U     |   n  á   ë  ç   Í  8  µ  '   î  k                  ¡  $   º  ±  ß     !  !   ª!     Ì!  .   ì!     "     ,"      @"                                     #   
   &            (      !                 $                                   %                                    	   "      )                              '           <strong>ERROR</strong>: Anonymous LDAP bind failed. Check the login credentials. <strong>ERROR</strong>: Anonymous LDAP bind failed. Either the LDAPS connection failed or the login credentials are incorrect. <strong>ERROR</strong>: Cannot connect to '%s'. <strong>ERROR</strong>: LDAP bind failed. Check the login credentials. <strong>ERROR</strong>: LDAP bind failed. Either the LDAPS connection failed or the login credentials are incorrect. <strong>ERROR</strong>: LDAP user ID search filter is inacuurate. The filter must contains '%user_id%'. <strong>ERROR</strong>: This user exists in LDAP, but has not been granted access to this installation of WordPress. Allows WordPress to authenticate users through LDAP Automatically create accounts for any and all users can authenticate to the LDAP? Base DN Base DN (e.g., <code>dc=example,dc=net</code>) Bind DN Bind DN (e.g., <code>cn=proxyuser,dc=example,dc=net</code>) Bind Password Default email domain Group Member Attribute Group Search Filter If the LDAP attribute 'mail' is blank, a user's email will be set to username@whatever-this-says If you use SSL connection or not, when LDAP connection. LDAP Group LDAP Server LDAP Server (e.g. <code>ldap.example.net</code>) LDAP attribute for group member (e.g., <code>memberuid</code>) LDAP filter for searching group (e.g., <code>(cn=%group%)</code>)<br />
This setting must contain <code>%group%</code> string. LDAP filter for searching user ID (e.g., <code>(uid=%user_id%)</code>)<br />
This setting must contain <code>%user_id%</code> string. List of LDAP groups which correspond to WordPress user roles.<br />
When a user is first created, his role will correspond to what is specified here.<br />
Format: <code>LDAP-Group=WordPress-Role;LDAP-Group=WordPress-Role;...</code><br />
E.g., <code>Soc-Faculty=faculty</code> or <code>Faculty=faculty;Students=subscriber</code><br />
A user will be created based on the first math, from left to right, so you should obviously put the more powerful groups first.<br />
NOTE: WordPress stores roles as lower case ( Faculty is stored as faculty )<br />
ALSO NOTE: LDAP groups are case-sensitive Options reseted. Password for database login account. RedGecko Reset Options Role Equivalent Groups Role Equivalent Groups Editor Should a new user be created automatically if not already in the WordPress database?<br />
Created users will obtain the role defined under &quot;New User Default Role&quot; on the <a href="options-general.php">General Options</a> page.
<br />
This setting is separate from the Role Equivalent Groups option, below.
<br />
<strong>Users with role equivalent groups will be created even if this setting is turned off</strong> (because if you didn't want this to happen, you would leave that option blank.) Simple LDAP Authentication Simple LDAP Authentication Options Use SSL connection with LDAP? User ID Search Filter WordPress Role http://redgecko.jp/ http://redgecko.jp/wp/ldap_auth/ Project-Id-Version: ã·ã³ãã« LDAP èªè¨¼ 1.0.1
Report-Msgid-Bugs-To: http://wordpress.org/tag/simple-ldap-authentication
POT-Creation-Date: 2009-05-29 19:40+0900
PO-Revision-Date: 2009-05-29 19:48+0900
Last-Translator: Yoshimitsu Mori <redgecko@redgecko.jp>
Language-Team: Japanese <redgecko@redgecko.jp>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
 <strong>ã¨ã©ã¼</strong>ï¼LDAP ã®å¿åãã¤ã³ãã«å¤±æãã¾ãããã­ã°ã¤ã³è³æ ¼ãç¢ºèªãã¦ãã ããã <strong>ã¨ã©ã¼</strong>ï¼LDAP ã®å¿åãã¤ã³ãã«å¤±æãã¾ãããLDAPS ã®æ¥ç¶ã«å¤±æããããã­ã°ã¤ã³è³æ ¼ãééã£ã¦ãã¾ãã <strong>ã¨ã©ã¼</strong>ï¼'%s' ã«æ¥ç¶ã§ãã¾ããã <strong>ã¨ã©ã¼</strong>ï¼LDAP ã®ãã¤ã³ãã«å¤±æãã¾ãããã­ã°ã¤ã³è³æ ¼ãç¢ºèªãã¦ãã ããã <strong>ã¨ã©ã¼</strong>ï¼LDAP ã®ãã¤ã³ãã«å¤±æãã¾ãããLDAPS ã®æ¥ç¶ã«å¤±æããããã­ã°ã¤ã³è³æ ¼ãééã£ã¦ãã¾ãã <strong>ã¨ã©ã¼</strong>ï¼LDAP ã® ID æ¤ç´¢ç¨ãã£ã«ã¿ãééã£ã¦ãã¾ãããã£ã«ã¿ã«ã¯ '%user_id%' ãå«ã¾ãã¦ããå¿è¦ãããã¾ãã <strong>ã¨ã©ã¼</strong>ï¼ãã®ã¦ã¼ã¶ã¯ LDAP ã«å­å¨ãã¾ãããWordPress ã¸ã®ã¢ã¯ã»ã¹ã¯è¨±å¯ããã¦ãã¾ããã WordPress ã§ LDAP ã«ããèªè¨¼ãå¯è½ã«ãã¾ã LDAP ã§èªè¨¼ãããå¨ã¦ã®ã¦ã¼ã¶ã«å¯¾ãèªåçã«ã¢ã«ã¦ã³ããä½æãã¾ããï¼ ãã¼ã¹ DN æ¤ç´¢ãè¡ãéã®ãã¼ã¹ DN ãæå®ãã¦ãã ãããï¼ä¾ï¼<code>dc=example,dc=net</code>ï¼ ç¹æ¨©ã®ãªããã¼ã¿ãã¼ã¹ã¦ã¼ã¶ (ãã¤ã³ã DN) LDAP ãã¼ã¿ãã¼ã¹ã«ã­ã°ã¤ã³ããã®ã«ä½¿ãããã¢ã«ã¦ã³ãåãå¥åãã¦ãã ãããï¼ä¾ï¼<code>cn=proxyuser,dc=example,dc=net</code>ï¼ ãã¼ã¿ãã¼ã¹ã­ã°ã¤ã³ã¢ã«ã¦ã³ãã®ãã¹ã¯ã¼ã (ãã¤ã³ãã»ãã¹ã¯ã¼ã) ããã©ã«ãã® E-Mail ãã¡ã¤ã³ ã°ã«ã¼ãã¡ã³ãã®å±æ§ ã°ã«ã¼ããæ¤ç´¢ããéã®ãã£ã«ã¿ LDAP ã® 'mail' å±æ§ãç©ºã®å ´åãã¦ã¼ã¶ã®ã¡ã¼ã«ã¢ãã¬ã¹ã¯ "ã¦ã¼ã¶å@ããã§ã®è¨­å®å¤"ã«ãªãã¾ãã LDAP ã§ã®æ¥ç¶æã« SSL ã§éä¿¡ãè¡ãããè¨­å®ãã¾ãã LDAP ã°ã«ã¼ã LDAP ãµã¼ã LDAP ãµã¼ããæå®ãã¦ãã ãããï¼ä¾ï¼<code>ldap.example.net</code>ï¼ ã°ã«ã¼ãã®ã¡ã³ãã¼æå ±ãå«ã¾ãã¦ããå±æ§ãæå®ãã¦ãã ãããï¼ä¾ï¼<code>memberuid</code>ï¼ ã°ã«ã¼ããæ¤ç´¢ããããã® LDAP ãã£ã«ã¿ãæå®ãã¦ãã ãããï¼ä¾ï¼<code>(cn=%group%)</code>ï¼<br />
ãã®è¨­å®ã«ã¯ãæå­å <code>%group%</code> ãå«ã¾ãã¦ããå¿è¦ãããã¾ãã ã¦ã¼ã¶ ID ãæ¤ç´¢ããããã® LDAP ãã£ã«ã¿ãæå®ãã¦ãã ãããï¼ä¾ï¼<code>(uid=%user_id%)</code>ï¼<br />
ãã®è¨­å®ã«ã¯ãæå­å <code>%user_id%</code> ãå«ã¾ãã¦ããå¿è¦ãããã¾ãã WordPress ã¦ã¼ã¶æ¨©éã«å¯¾å¿ãã LDAP ã°ã«ã¼ãããªã¹ãã¢ãããã¦ãã ããã<br />
ã¦ã¼ã¶ãæåã«ä½æãããéããã®ã¦ã¼ã¶ã®æ¨©éã¯ããã§æå®ãããè©²å½ã®ç©ã«ãªãã¾ãã<br />
ãã©ã¼ãããï¼<code>LDAPã°ã«ã¼ã=WordPressæ¨©é;LDAPã°ã«ã¼ã=WordPressæ¨©é;...</code><br />
ä¾ï¼<code>Soc-Faculty=faculty</code> ãããã¯ <code>Faculty=faculty;Students=subscriber</code><br />
ã¦ã¼ã¶ã¯å·¦ããå³ã«åãã¦å¦çãããæåã®ä¸è´æ¡ä»¶ã«åºã¥ãä½æãããããããã£ã¨ãæ¨©éã®å¼·ãã°ã«ã¼ããåã«æ¸ãã¹ãã§ãã<br />
æ³¨ï¼WordPress ã¯æ¨©éãå°æå­ã§ä¿å­ãã¾ããï¼Faculty ã¯ faculty ã¨ãã¦ä¿å­ããã¾ãï¼<br />
æ³¨ï¼LDAP ã®ã°ã«ã¼ãã¯å¤§æå­å°æå­ãåºå¥ãã¾ãã è¨­å®ããªã»ããããã¾ããã LDAP ãã¼ã¿ãã¼ã¹ã«ã­ã°ã¤ã³ããã®ã«ä½¿ããããã¹ã¯ã¼ããå¥åãã¦ãã ããã RedGecko è¨­å®ããªã»ãã èªåã°ã«ã¼ãæ¨©é èªåã°ã«ã¼ãæ¨©éã¨ãã£ã¿ WordPress ã®ãã¼ã¿ãã¼ã¹ã«ã¦ã¼ã¶ãå­å¨ããªãå ´åãèªåçã«æ°ããã¦ã¼ã¶ãä½æãã¾ããï¼<br />
ä½æãããã¦ã¼ã¶ã¯ã<a href="options-general.php">ä¸è¬è¨­å®</a>ãã¼ã¸ã® &quot;æ°è¦ã¦ã¼ã¶ã¼ã®ããã©ã«ãæ¨©é&quot; ã«æ²¿ã£ãæ¨©éãä¸ãããã¾ãã
<br />
ãã®è¨­å®ã¯ä¸ã«ããèªåã°ã«ã¼ãæ¨©éãªãã·ã§ã³ã¨ã¯ç¬ç«ãã¦åä½ãã¾ãã
<br />
<strong>ãã®è¨­å®ããªãã®å ´åã§ããèªåã°ã«ã¼ãæ¨©éã«å¾ã£ã¦ã¦ã¼ã¶ã¯ä½æããã¾ãã</strong>ï¼ãã®åä½ãæã¾ãããªãã¨æãã®ã§ããã°ããã ãã®è¨­å®ãç©ºã«ãã¦ããå¿è¦ãããã¾ããï¼ ã·ã³ãã« LDAP èªè¨¼ ã·ã³ãã« LDAP èªè¨¼ã®è¨­å® SSL æ¥ç¶ãä½¿ãã¾ããï¼ ã¦ã¼ã¶ ID ãæ¤ç´¢ããéã®ãã£ã«ã¿ WordPress æ¨©é http://redgecko.jp/ http://redgecko.jp/wp/ldap_auth/ 