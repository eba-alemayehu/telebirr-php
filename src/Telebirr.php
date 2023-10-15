<?php
namespace telebirr;

use phpseclib3\Crypt\PublicKeyLoader;

class Telebirr
{
    private $api;
    private $app_id;
    private $ussd;
    private $sign;
    private $data_from_telebirr;
    private $rsa_public_key;

    function __construct($app_id, $app_key, $public_key, $notify_url, $receive_name, $return_url, $short_code, $subject,
                         $timeout_express, $total_amount, $nonce, $out_trade_no,
                         $api = "http://196.188.120.3:10443/service-openup/toTradeWebPay")
    {
        $this->api = $api;
        $this->app_id = $app_id;
        $ussd = [
            "appId" => $this->app_id,
            "notifyUrl" => $notify_url,
            "outTradeNo" => $out_trade_no,
            "receiveName" => $receive_name,
            "returnUrl" => $return_url,
            "shortCode" => $short_code,
            "subject" => $subject,
            "timeoutExpress" => $timeout_express,
            "totalAmount" => $total_amount,
            "nonce" => $nonce,
            "timestamp" => strval(round(microtime(true) * 1000) . "<br>")
        ];
        $this->ussd = $this->_encrypt_ussd($ussd, $public_key);
        $this->sign = $this->_sign($ussd, $app_key);
        $this->data_from_telebirr = file_get_contents('php://input');
        $this->rsa_public_key = PublicKeyLoader::load($public_key);
    }

    function _encrypt_ussd($ussd, $public_key)
    {
        $ussd_json = json_encode($this->ussd);
        return $this->encryptRSA($ussd_json, $public_key);
    }

    function encryptRSA($data, $public)
    {
        $pubPem = chunk_split($public, 64, "\n");
        $pubPem = "-----BEGIN PUBLIC KEY-----\n" . $pubPem . "-----END PUBLIC KEY-----\n";
        $public_key = openssl_pkey_get_public($pubPem);
        if (!$public_key) {
            die('invalid public key');
        }
        $crypto = '';
        foreach (str_split($data, 117) as $chunk) {
            $return = openssl_public_encrypt($chunk, $cryptoItem, $public_key);
            if (!$return) {
                return ('fail');
            }
            $crypto .= $cryptoItem;
        }
        $ussd = base64_encode($crypto);
        return $ussd;
    }

    function _sign($ussd, $app_key)
    {
        $data = $ussd;
        $data['appKey'] = $app_key;
        ksort($data);

        $StringA = '';
        foreach ($data as $k => $v) {
            if ($StringA == '') {
                $StringA = $k . '=' . $v;
            } else {
                $StringA = $StringA . '&' . $k . '=' . $v;
            }
        }
        return hash("sha256", $StringA);
    }


    function _request_params()
    {
        return [
            "appid" => $this->app_id,
            "sign" => $this->sign,
            "ussd" => $this->ussd
        ];
    }

    function send_request()
    {
        $client = new GuzzleHttp\Client();
        $response = $client->post($this->api, [
            GuzzleHttp\RequestOptions::JSON => $this->_request_params()
        ]);
        return $response;
    }

    public static function decrypt_RSA($public_key)
    {
        $data_from_telebirr = file_get_contents('php://input');
        $DECRYPT_BLOCK_SIZE = 256;
        $decrypted = '';

        //decode must be done before spliting for getting the binary String
        $data = str_split(base64_decode($data_from_telebirr), $DECRYPT_BLOCK_SIZE);

        foreach ($data as $chunk) {
            $partial = '';

            $decryptionOK = openssl_public_decrypt($chunk, $partial, $public_key, OPENSSL_PKCS1_PADDING);

            if ($decryptionOK === false) {
                return false;
            }
            $decrypted .= $partial;
        }
        return $decrypted;
    }
}
