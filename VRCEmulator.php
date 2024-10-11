<?php

/*
	
	Note some part of code a bit ghetto
	
	however, 2 things you can optimize: read() and write(), 
	you can find SQL struct in .\VRChatMassRegBot\convert._to_sql.js
	
	GetShuffle() and shuffle.php is a random index picked by cron script for shuffle the account
*/

function GetShuffle()
{
    return include('shuffle.php');
}

const vrchat_api = "api.vrchat.cloud";
const vrchat_api_proxy = "";//"http://127.0.0.1:9093";

class VRCEMC 
{
    function mac_address_gen()
    {
        $randomBytes = array_map(function() {
            return random_int(0, 254);
        }, range(1, 5));
    
        $byteString = implode(array_map('chr', $randomBytes));
        $sha1Hash = sha1($byteString, true);
        $macAddress = bin2hex($sha1Hash);
        return $macAddress;
    }
    
	// why name so weird and don't cache the result?
	// cuz this been file read/write
    function read($id = -1)
    {
        if($id == -1)
            $id = GetShuffle();
        $db = Flight::db();
        return $db->fetchRow("SELECT * FROM `vrc_session` WHERE id=?", [$id]);
    }
    
    function write($content, $id = -1)
    {
        if($id == -1)
            $id = GetShuffle();
        $db = Flight::db();
        $stmt = $db->runQuery("UPDATE `vrc_session` SET `authcookie` = ?, `2fa` = ? WHERE `vrc_session`.`id` = ?;", [$content['authcookie'], $content['2fa'], $id]);
    }
    
    function SetAccountStatus($id = -1, $status)
    {
        if($id == -1)
            $id = GetShuffle();
        $db = Flight::db();
        $stmt = $db->runQuery("UPDATE `vrc_session` SET `account_status` = ? WHERE `vrc_session`.`id` = ?;", [$status, $id]);
    }
    
    function AES_CBC_Encrypt($data) {
        $method = 'aes-256-cbc';
    	$key = 'im really seriously not joking. ';
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));
        $encrypted = openssl_encrypt($data, $method, $key, OPENSSL_RAW_DATA, $iv);
        $encrypted_data = base64_encode($iv . $encrypted);
        return $encrypted_data;
    }
    
    function get_cookie($response)
    {
        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $response, $matches);
        $returnCookies = array();
        foreach($matches[1] as $item) {
            parse_str($item, $cookie);
            $returnCookies = array_merge($returnCookies, $cookie);
        }
        return $returnCookies;
    }
    
	/*
		Here is important,
		the header is how VRChat HTTP Api identify the client type (Web, Client, SDK)
		User-Agent, X-Client-Version, X-Platform etcs...
		the current headers are from vrchat client
	*/
    function buildvrchatheader($hasAuth = false, $contentType = "")
    {
        $row = $this->read();
        $header = array(
            'X-MacAddress: ' . $row['macaddr'],
            'X-Client-Version: 2024.3.2p3-1507--Release',
            'X-Platform: standalonewindows',
            'X-GameServer-Version: Release_1343',
            'X-Unity-Version: 2022.3.22f1-DWR',
            'X-Store: steam',
            'Host: api.vrchat.cloud',
            'Accept-Encoding: identity',
            'Connection: Keep-Alive, TE',
            'TE: identity',
            'User-Agent: VRC.Core.BestHTTP'
        );
        if($hasAuth)  // here is like for login
            array_push($header, 'Authorization: Basic ' . base64_encode(urlencode($row['user']) . ":" . urlencode($row['pass'])));
        if(!empty($contentType)) // some api need this
            array_push($header, 'Content-Type: ' . $contentType);
        return $header;
    }
    
	// Generic request wrapper for vrchat api
    function request_api_as_client($endpoint, $id, $extraPath = '')
    {
        $cache = $this->read();
        if(!isset($cache['2fa']) || !isset($cache['authcookie']))
        {
            Flight::json(array('msg' => 'please login'));
            return false;
        }
        
        $request = curl_init();
        curl_setopt($request, CURLOPT_URL, $endpoint.$id.$extraPath);
        $headers = $this->buildvrchatheader();
    
        curl_setopt($request, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($request, CURLOPT_PROXY, vrchat_api_proxy);
        
        $cookies = 'auth=' . $cache['authcookie'] . '; twoFactorAuth=' . $cache['2fa'];
        
        curl_setopt($request, CURLOPT_COOKIE, $cookies);
        curl_setopt($request, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($request);
        
        curl_close($request);
        
        return $response;
    }
    
	// generate download link
    function GenerateDownloadLink($url, $cookie, $filename, $expire)
    {
        $_Header = $this->buildvrchatheader();
        $Data = array(
            'Url' => $url,
            'Expire' => $expire,
            'FileName' => $filename,
            'Headers' => $_Header,
            'Cookie' => $cookie
        );
        return "https://dl-gate.example.com/?param=" . urlencode($this->AES_CBC_Encrypt(json_encode($Data)));
    }

    // autoanswered by worker
    function confirm_login()
    {
        
    }

	// $mail like example@gmail.com
    function EmailGetCode($mail)
    {
        $mail = strtolower($mail);
       
        $request = curl_init();
        curl_setopt($request, CURLOPT_URL, "https://mail.example.com/emailotp/$mail"); 
		// ^ that api will return a parsed code from vrchat email, just make your own implement
	
        curl_setopt($request, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($request);
        
        curl_close($request);
        
        $result = json_decode($response, true);
        if($result['code'] != 0)
        {
            return false;
        }
        return $result['data']['code'];
    }

    function TryLogin()
    {
        $cache = $this->read();
        
        $request = curl_init();
        curl_setopt($request, CURLOPT_URL, "https://" . vrchat_api . "/api/1/auth/user");
        $headers = $this->buildvrchatheader(true, 'application/x-www-form-urlencoded');
    
        curl_setopt($request, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($request, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($request, CURLOPT_HEADER, true);
        curl_setopt($request, CURLOPT_PROXY, vrchat_api_proxy);
        $response = curl_exec($request);
        
        curl_close($request);
        
        $returnCookies = $this->get_cookie($response);
        
        // debug lol
        $f = fopen("logs.txt","w");
        fwrite($f, json_encode($response));
        fclose($f);
        //Flight::json($response);
        
        if(!isset($returnCookies['auth']))
        {
            return 1; // failed try login, could be need email click verify
        }
        
        $cache['authcookie'] = $returnCookies['auth'];
        $this->write($cache);
        
        $needOtp = strpos($response, "emailOtp");
        if ($needOtp === false) {
            return 0;  // ok
        }
        return 2;   // need email verify
    }
    
    function LogOut()
    {
        $cache = $this->read();
        
        $request = curl_init();
        curl_setopt($request, CURLOPT_URL, "https://" . vrchat_api . "/api/1/logout");
        $headers = $this->buildvrchatheader();
    
        curl_setopt($request, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($request, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($request, CURLOPT_HEADER, true);
        curl_setopt($request, CURLOPT_PROXY, vrchat_api_proxy);
        
        $cookies = 'auth=' . $cache['authcookie'];
        curl_setopt($request, CURLOPT_COOKIE, $cookies);
        
        $response = curl_exec($request);
        
        curl_close($request);
    }
    
    function EmailVerify($code)
    {
        $cache = $this->read();
        if(!isset($cache['authcookie']))
        {
            return false;
        }
        
        $request = curl_init();
        curl_setopt($request, CURLOPT_URL, "https://" . vrchat_api . "/api/1/auth/twofactorauth/emailotp/verify");
        $headers = $this->buildvrchatheader(false, 'application/json');
    
        curl_setopt($request, CURLOPT_HTTPHEADER, $headers);
        
        $cookies = 'auth=' . $cache['authcookie'];
        
        $PostFields = array(
            'code' => $code
        );
        
        curl_setopt($request, CURLOPT_COOKIE, $cookies);
        curl_setopt($request, CURLOPT_POST, true);
        curl_setopt($request, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($request, CURLOPT_POSTFIELDS, json_encode($PostFields));
        curl_setopt($request, CURLOPT_HEADER, true);
        curl_setopt($request, CURLOPT_PROXY, vrchat_api_proxy);
        
        $response = curl_exec($request);
        
        curl_close($request);
        
        $returnCookies = $this->get_cookie($response);
        
        if(!isset($returnCookies['twoFactorAuth']))
        {
            return false;
        }
        
        $cache['2fa'] = $returnCookies['twoFactorAuth'];
        $this->write($cache);
        return true;
    }

    function login_standlone()
    {
        $cache = $this->read();
		/*
			Here is bit ugly codes,
			let me explain, first we check if 2fa is set, the 2 things are required to login - authcookie and 2fa
			but authcookie can be exist even not logged in.
			then we check the account_status, it should be 0 by default, then we call TryLogin() for attempts
			so we know if any extra verify is needed (email confirm click or email code)
			
			then we have account status 1 or 2, 
			account_status defines:
			0 - not logged in and empty data
			1 - authcookie, midway to login
			2 - logged in, able to request api
			9 - bugged, unknown error encountered
			
			once we need to email code, call EmailGetCode() then request to VRChat Api to get 2fa cookie
			or error it and tell user.
			
			to be honest, i think nodejs would do this way better than PHP...
		*/
        if(empty($cache['2fa']))
        {
            switch($cache['account_status'])
            {
                case 0:
                {
                    $trystatus = $this->TryLogin();
                    $code = "#A";
                    switch($trystatus)
                    {
                        case 0:
                            $this->SetAccountStatus($cache['id'], 2); // email code
                            $code = "#UVC";
                        break;
                        case 2:
                            $this->SetAccountStatus($cache['id'], 1); // email confirm
                            $code = "#AWU";
                        break;
                        
                    }
                    return array("code" => 1, "msg" => 'Please wait few seconds and try again! Code: ' . $code);
                }    
                break;
                case 1:
                {
                    $verifycode = $this->EmailGetCode($cache['email']);
                    $msg = "Error #NEC!";
                    if($verifycode)
                    {
                        if($this->EmailVerify($verifycode))
                        {
                            $this->SetAccountStatus($cache['id'], 2);
                            $msg = "You are going! One more retry!";
                        }
                        else 
                        {
                            $this->SetAccountStatus($cache['id'], 9); // requires manually check
                            $msg = "Unknown Error #EMF, report this for help :(";
                        }
                    }
                    return array("code" => 1, "msg" => "Please try again in a minute! " . $msg);
                }
                break;
            }
            $this->SetAccountStatus($cache['id'], 0);
            $cache['authcookie'] = '';
            $this->write($cache);
            return array("code" => 2, "msg" => "unknown failure #AXX");
        }
		// here is check for unexcepted case, usually will not happen just in case 
        if($cache['account_status'] == 0)
        {
            $this->SetAccountStatus($cache['id'], 0);
            $cache['2fa'] = '';
            $cache['authcookie'] = '';
            $this->write($cache);
            return  array("code" => 2, "msg" => "Please retry more times!");
        }
        if($cache['account_status'] != 2) // same, just in case
        {
            $this->SetAccountStatus($cache['id'], 0);
            $cache['2fa'] = '';
            $cache['authcookie'] = '';
            $this->write($cache);
            return array("code" => 2, "msg" => "ID-Downloader could be bugged, report this for help");
        }
        
        $request = curl_init();
        curl_setopt($request, CURLOPT_URL, "https://" . vrchat_api . "/api/1/auth/user");
        $headers = $this->buildvrchatheader(true, 'application/x-www-form-urlencoded');

        curl_setopt($request, CURLOPT_HTTPHEADER, $headers);
        
        $cookies = 'auth=' . $cache['authcookie'] . '; twoFactorAuth=' . $cache['2fa'];
        
        curl_setopt($request, CURLOPT_COOKIE, $cookies);
        curl_setopt($request, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($request, CURLOPT_HEADER, true);
        curl_setopt($request, CURLOPT_PROXY, vrchat_api_proxy);
        $response = curl_exec($request);
        
        curl_close($request);
        
		// some checks, sometimes it happens, you need test yourself
        if(strpos($response, "It looks like you're logging in from somewhere new!") != false)
        {
            $this->SetAccountStatus($cache['id'], 0);
            $cache['2fa'] = '';
            $this->write($cache);
            return array("code" => 3, "msg" => "general failure #NLG, please retry");
        }
        
        if(strpos($response, "Logging in from too many places?") != false)
        {
            $this->SetAccountStatus($cache['id'], 0);
            $cache['2fa'] = '';
            $cache['authcookie'] = '';
            $this->write($cache);
            return array("code" => 3, "msg" => "general failure #CDL, please retry");
        }
        
		// should return your userinfo
        if(strstr($response, 'displayName') != false)
        {
            return array("code" => 0, "msg" => "");
        }
        
		// update the cookie like the vrchat itself
        $returnCookies = $this->get_cookie($response);
        if(!isset($returnCookies['auth']))
        {
            $this->SetAccountStatus($cache['id'], 0);
            $cache['2fa'] = '';
            $cache['authcookie'] = '';
            $this->write($cache);
            return array("code" => 2, "msg" => "unknown failure #KDE");
        }
        
        $cache['authcookie'] = $returnCookies['auth'];
        $this->write($cache);
        
        return array("code" => 0, "msg" => "");
    }
    
    function check_id_valid($prefix, $id)
    {
        $offset = strpos($id, $prefix);
        if($offset === false)
            return false;
        $guid = substr($id, strlen($prefix));
        if ($guid && preg_match('/^[a-f\d]{8}(-[a-f\d]{4}){4}[a-f\d]{8}$/i', $guid)) { }
        else {return false;}
        return true;
    }

    function handle_id_download($prefix, $api, $id, $extension, $limitAccess, $filterfunc, $midwayfunc = null, $debug = false)
    {
        if(!$this->check_id_valid($prefix, $id))
        {
            return Flight::json(array("code" => 1, "msg" => "illegal id"));
        }
        
        $login_info = $this->login_standlone();
        if($login_info['code'] > 0)
        {
            return Flight::json(array("code" => 2, "msg" => $login_info['msg'] . " [report to admin if this error repeats]"));
        }
        
        $decoded = json_decode($this->request_api_as_client("https://" . vrchat_api . "/api/1/" . $api . '/', $id), true);
        if(isset($decoded["error"]) === true)
        {
            return Flight::json(array("code" => 3, "msg" => $decoded["error"]["message"]));
        }
        if($debug)
        {
            return Flight::json(array("code" => 0, "data" => $decoded));
        }
        
        if($midwayfunc != null)
        {
            return Flight::json($midwayfunc($decoded));
        }
        $url = $filterfunc($decoded);
        if($url === null)
        {
            return Flight::json(array("code" => 4, "msg" => "Failed to generate download url."));
        }
		
        $cache = $this->read();
        $cookies = 'auth=' . $cache['authcookie'] . '; twoFactorAuth=' . $cache['2fa'];
        
        $expireTime = time() + (30 * 60);
        
        $encrypted = $this->GenerateDownloadLink($url, $cookies, $id . $extension, $expireTime);
        
        //$this->LogOut();
        
        return Flight::json(array("code" => 0, "dlurl" => $encrypted));
    }

    function generate_preview($response)
    {
        $id = $response['id'];
        // no cookie needed for image
        $url = $response['assetUrl'];
        if(strpos($id, "wrld_") !== false)
        {
            $url = $response['unityPackages'][count($response['unityPackages']) - 1]['assetUrl'];
        }
        
        $cache = $this->read();
        $cookies = 'auth=' . $cache['authcookie'] . '; twoFactorAuth=' . $cache['2fa'];
        $expireTime = time() + (30 * 60);
        $encrypted = $this->GenerateDownloadLink($url, $cookies, $id . $extension, $expireTime);
        
        $bannerUrl = $response['imageUrl'];
        return array(
            "code" => 0,
            "data" => array(
                "id" => $id,
                "name" => $response['name'],
                "authorName" => $response['authorName'],
                "authorId" => $response['authorId'],
                "banner" => $bannerUrl,
                "assetUrl" => $encrypted,
            ) 
        ); 
    }
    
    function id_download_from_cache($id, $filterfunc)
    {
        $db = Flight::db();
        $stmt = $db->runQuery("SELECT * FROM `db_shared_a_w` WHERE `guid` = ?", [$id]);
        if ($stmt->rowCount() > 0) {
            while ($row = $stmt->fetch()) {
                
                $og_response = json_decode(base64_decode($row['og_respond']), true);
                $url = $filterfunc($og_response);
        
                $expireTime = time() + (30 * 60);
        
                $cache = $this->read();
                $cookies = 'auth=' . $cache['authcookie'] . '; twoFactorAuth=' . $cache['2fa'];
        
                $encrypted = $this->GenerateDownloadLink($url, $cookies, $id . '.vrca', $expireTime);
                
                return array("code" => 0, "dlurl" => $encrypted);
            }
        } 
        else {
            return array("code" => -1, "msg" => "not found");
        }
        return array("code" => -1, "msg" => "unknown error");
    }

    // =======================================================================
    // Route
    function OnGetAvatar($id) {
        return $this->handle_id_download("avtr_", "avatars", $id, ".vrca", true, function($response){
            return $response['assetUrl'];
        });
    }

    function OnGetAvatarImg($id) {
        return $this->handle_id_download("avtr_", "avatars", $id, ".png", false, function($response){
            return $response['imageUrl'];
        });
    }

    function OnGetAvatarInfo($id) {
        return $this->handle_id_download("avtr_", "avatars", $id, "", true, null, function($response){
            return $this->generate_preview($response);
        });
    }
    
    function OnGetWorld($id) {
        return $this->handle_id_download("wrld_", "worlds", $id, ".vrcw", true, function($response){
            return $response['unityPackages'][count($response['unityPackages']) - 1]['assetUrl'];
        }); 
    }

    function OnGetWorldImg($id) {
        return $this->handle_id_download("wrld_", "worlds", $id, ".png", false, function($response){
            return $response['imageUrl'];
        }); 
    }

    function OnGetWorldInfo($id) {
        return $this->handle_id_download("wrld_", "worlds", $id, "", true,  null, function($response){
            return $this->generate_preview($response);
        });
    }
}

$VRCEMC = new VRCEMC();

Flight::route('/iddl/avatar/@id', [ $VRCEMC, 'OnGetAvatar' ]);
Flight::route('/iddl/avatarimg/@id', [ $VRCEMC, 'OnGetAvatarImg' ]);
Flight::route('/iddl/avatarinfo/@id', [ $VRCEMC, 'OnGetAvatarInfo' ]);

Flight::route('/iddl/world/@id', [ $VRCEMC, 'OnGetWorld' ]);
Flight::route('/iddl/worldimg/@id', [ $VRCEMC, 'OnGetWorldImg' ]);
Flight::route('/iddl/worldinfo/@id', [ $VRCEMC, 'OnGetWorldInfo' ]);

?>