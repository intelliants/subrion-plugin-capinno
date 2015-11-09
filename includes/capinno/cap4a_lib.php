<?php

define("CAP4A_VERIFY_SERVER", "part.cap4a.com");

/**
 * Encodes the given data into a query string format
 * @param $data - array of string elements to be encoded
 * @return string - encoded request
 */
function _cap4a_qsencode($data)
{
	$req = "";
	foreach ($data as $key => $value)
	{
		if ($req)
			$req .= '&';

		$req .= $key . '=' . urlencode(stripslashes($value));
	}

	return $req;
}

/**
 * Submits an HTTP POST to a Cap4a server
 * @param string $host
 * @param string $path
 * @param array $data
 * @param int port
 * @return array response
 */
function _cap4a_http_post($host, $path, $data, $port = 80)
{
	global $FORCE_POST_CHARSET;

	$semicolon_pos = strpos($_SERVER["CONTENT_TYPE"], ";");
	if ($semicolon_pos)
		$charset = trim(substr($_SERVER["CONTENT_TYPE"], $semicolon_pos+1));

	if (!empty($_POST["_charset_"]))
		$charset = $_POST["_charset_"];

	if (!empty($FORCE_POST_CHARSET))
		$charset = $FORCE_POST_CHARSET;

	if (empty($charset))
		$charset = "utf-8";

	$data['_charset_'] = $charset;

	$req = _cap4a_qsencode($data);

	$http_request  = "POST $path HTTP/1.0\r\n";
	$http_request .= "Host: $host\r\n";
	$http_request .= "Content-Type: application/x-www-form-urlencoded; charset=" . $charset . "\r\n";
	//    $http_request .= "Content-Type: application/x-www-form-urlencoded\r\n";
	$http_request .= "Content-Length: " . strlen($req) . "\r\n";
	$http_request .= "User-Agent: Cap4a/PHP\r\n";
	$http_request .= "\r\n";
	$http_request .= $req;

	/*  DEBUG
		echo "<br>Host: " . $host;
		echo "<br>Path: " . $path;
		echo "<br>Request: ";
		echo nl2br($http_request);
	//  END DEBUG */

	$response = '';
	if( false == ( $fs = @fsockopen($host, $port, $errno, $errstr, 10) ) )
	{
		die ('Could not open socket: ' . $errstr);
	}

	fwrite($fs, $http_request);

	while ( !feof($fs) )
		$response .= fgets($fs, 1160); // One TCP-IP packet
	fclose($fs);

	/*  DEBUG
	echo "<br>Response: ";
	echo nl2br($response);
	//  END DEBUG */

	$response = explode("\r\n\r\n", $response, 2);

	return $response;
}

/**
 * A Cap4aResponse is returned from cap4a_check_answer()
 */
class Cap4aResponse
{
	var $is_valid;
	var $error;
	var $image_url;
}

/**
 * Calls an HTTP POST function to verify if the user's guess was correct
 * @param string $server
 * @param string $privkey
 * @param string $remoteip
 * @param string $challenge
 * @param string $response
 * @param array $extra_params an array of extra variables to post to the server
 * @return Cap4aResponse
 */
function cap4a_check_answer($server, $privkey, $remoteip, $challenge, $response, $extra_params = array())
{
	if ($privkey == null || $privkey == '')
	{
		die ("To use Cap4a you must get an API key from <a href='http://partner.cap4a.com/registration.php'>http://partner.cap4a.com/registration.php</a>");
	}

	if ($remoteip == null || $remoteip == '')
	{
		die ("For security reasons, you must pass the remote ip to Cap4a");
	}

	//discard spam submissions
	if ($challenge == null || strlen($challenge) == 0 || $response == null || strlen($response) == 0)
	{
		$objResponse = new Cap4aResponse();
		$objResponse->is_valid = false;
		$objResponse->error = 'incorrect-captcha-sol';

		return $objResponse;
	}

	if (empty($server))
		$server = CAP4A_VERIFY_SERVER;
	$path = "";

	$pos_slash_last = strrpos($server, "/");
	while ($pos_slash_last !== false && $pos_slash_last > 8)
	{
		$path = substr($server, $pos_slash_last) . $path;
		$server = substr($server, 0, $pos_slash_last);

		$pos_slash_last = strrpos($server, "/");
	}


	$server_response = _cap4a_http_post ($server, $path . "/authenticate.jsp",
		array (
			'privatekey' => $privkey,
			'remoteip' => $remoteip,
			'challenge' => $challenge,
			'response' => $response
		)
		+ $extra_params
	);

	$answers = explode ("\n", $server_response[1]);

	$objResponse = new Cap4aResponse();

	if (trim ($answers[0]) == 'true')
	{
		$objResponse->is_valid = true;
		$objResponse->image_url = trim($answers[1]);
	}
	else
	{
		$objResponse->is_valid = false;
		if (!empty($answers[1]))
			$objResponse->error = trim($answers[1]);
		else
			$objResponse->error = "Unknown error";
	}

	return $objResponse;
}