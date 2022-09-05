<?php

/**
 * 亚马逊销售合作伙伴授权API (Amazon网页授权流程/生成签名/获取RDT受限token信息-PII)
 * simple-amazon-selling-partner-api
 * Class AmazonSellingPartnerApi
 */
class AmazonSellingPartnerApi
{

    const API_HOST = 'https://api.amazon.com';
    const USER_AGENT = 'AmazonSellingPartner Client/1.0 (Language=PHP/7.1.8;Platform=CentOS7)';

    protected $applicationId;
    protected $clientId;
    protected $clientSecret;
    protected $accessToken;
    protected $accessKeyId;
    protected $secretAccessKey;
    protected $endpoint;
    protected $siteCode;
    protected $region;
    protected $sessionToken;
    protected $marketplaceId;
    protected $sellingPartnerId;
    protected $curlOption = [];
    protected $withSecurityToken = true;

    /**
     * AmazonSellingPartnerApi constructor.
     * @param $sellingPartnerId
     * @param $siteCode
     * @param array $developConfig
     * @throws Exception
     */
    protected function __construct($sellingPartnerId, $siteCode, $developConfig = [])
    {
        $this->sellingPartnerId = $sellingPartnerId;
        $this->siteCode = strtoupper($siteCode);
        $this->initAccountConfig();
        $this->initDevelopConfig($developConfig);
    }

    /**
     * 开发者信息
     * @param array $developConfig
     */
    protected function initDevelopConfig($developConfig = [])
    {
        $this->applicationId = $developConfig['applicationId'] ?? '';
        $this->clientId = $developConfig['clientId'] ?? '';
        $this->clientSecret = $developConfig['clientSecret'] ?? '';
        $this->accessKeyId = $developConfig['accessKeyId'] ?? '';
        $this->secretAccessKey = $developConfig['secretAccessKey'] ?? '';
    }

    /**
     * @throws Exception
     */
    protected function initAccountConfig()
    {
        $regionCodeMap = [
            'us-east-1' => ['CA', 'US', 'MX', 'BR'],
            'eu-west-1' => ['ES', 'GB', 'FR', 'NL', 'DE', 'IT', 'SE', 'TR', 'AE', 'IN', 'PL', 'SA'],
            'us-west-2' => ['SG', 'AU', 'JP']
        ];
        $endpointApiMap = [
            'us-west-2' => 'sellingpartnerapi-fe.amazon.com',
            'us-east-1' => 'sellingpartnerapi-na.amazon.com',
            'eu-west-1' => 'sellingpartnerapi-eu.amazon.com',
        ];
        $siteMarketplaceIdMap = [
            'CA' => 'A2EUQ1WTGCTBG2',
            'US' => 'ATVPDKIKX0DER',
            'MX' => 'A1AM78C64UM0Y8',
            'BR' => 'A2Q3Y263D00KWC',

            'ES' => 'A1RKKUPIHCS9HS',
            'GB' => 'A1F83G8C2ARO7P',
            'FR' => 'A13V1IB3VIYZZH',
            'NL' => 'A1805IZSGTT6HS',
            'DE' => 'A1PA6795UKMFR9',
            'IT' => 'APJ6JRA9NG5V4',
            'SE' => 'A2NODRKZP88ZB9',
            'TR' => 'A33AVAJ2PDY3EV',
            'AE' => 'A2VIGQ35RCS4UG',
            'IN' => 'A21TJRUUN4KGV',
            'PL' => 'A1C3SOZRARQ6R3',
            'SA' => 'A17E79C6D8DWNP',

            'SG' => 'A19VAU5U5O7RUS',
            'AU' => 'A39IBJ37TRP1C6',
            'JP' => 'A1VC38T7YXB528',
        ];
        foreach ($regionCodeMap as $region => $siteCodeMap) {
            if (in_array($this->siteCode, $siteCodeMap)) {
                $this->region = $region;
                break;
            }
        }
        if (empty($this->region)) {
            throw new Exception('region not found.');
        }
        $this->endpoint = isset($endpointApiMap[$this->region]) ? $endpointApiMap[$this->region] : '';
        if (empty($this->endpoint)) {
            throw new Exception('endpoint not found.');
        }
        if (isset($siteMarketplaceIdMap[$this->siteCode])) {
            $this->marketplaceId = $siteMarketplaceIdMap;
        }
    }

    /**
     * 获取授权地址
     * @param string $state
     * @param string $version
     * @return string
     * @throws Exception
     */
    protected function getAuthUrl($state = 'my-test-state', $version = 'v1')
    {
        $siteAuthUrl = [
            'CA' => 'https://sellercentral.amazon.ca/',
            'US' => 'https://sellercentral.amazon.com/',
            'MX' => 'https://sellercentral.amazon.com.mx/',
            'BR' => 'https://sellercentral.amazon.com.br/',
            'SG' => 'https://sellercentral.amazon.sg/',
            'AU' => 'https://sellercentral.amazon.com.au/',
            'JP' => 'https://sellercentral-japan.amazon.com/',
            'AE' => 'https://sellercentral.amazon.ae/',
            'IN' => 'https://sellercentral.amazon.in/',
            'ES' => 'https://sellercentral.amazon.es/',
            'GB' => 'https://sellercentral.amazon.co.uk/',
            'FR' => 'https://sellercentral.amazon.fr/',
            'NL' => 'https://sellercentral.amazon.nl/',
            'DE' => 'https://sellercentral.amazon.de/',
            'IT' => 'https://sellercentral.amazon.it/',
            'SE' => 'https://sellercentral.amazon.se/',
            'TR' => 'https://sellercentral.amazon.com.tr/',
            'PL' => 'https://sellercentral.amazon.pl/',
            'SA' => 'https://sellercentral.amazon.sa/',
        ];
        if (!isset($siteAuthUrl[$this->siteCode])) {
            throw new Exception('not found site auth url.');
        }
        $queryArr = [
            'application_id' => $this->applicationId,
            'state' => $state,
            'version' => $version,
        ];
        return $siteAuthUrl[$this->siteCode] . 'apps/authorize/consent?' . http_build_query($queryArr);
    }

    /**
     * 通过code获取token
     * @param $code
     * @return array
     */
    protected function getAccessToken($code)
    {
        $tokenUrl = self::API_HOST . '/auth/o2/token';
        $data = [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
        ];
        $header = ['Content-Type: application/x-www-form-urlencoded;charset=UTF-8'];
        $responseArr = $this->curlRequest($tokenUrl, $data, $header);
        return $responseArr;
    }

    /**
     * 刷新token
     * @param $refreshToken
     * @return array
     */
    protected function refreshAccessToken($refreshToken)
    {
        $tokenUrl = self::API_HOST . '/auth/o2/token';
        $data = [
            'grant_type' => 'refresh_token',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'refresh_token' => $refreshToken,
        ];
        $header = [
            'Content-Type: application/x-www-form-urlencoded;charset=UTF-8'
        ];
        $responseArr = $this->curlRequest($tokenUrl, $data, $header);
        return $responseArr;
    }

    /**
     * 获取授权RTD token
     * @param $method
     * @param $path
     * @param $dataElements
     * @return array
     */
    protected function getRestrictedToken($method, $path, $dataElements)
    {
        $uri = '/tokens/2021-03-01/restrictedDataToken';
        $queryParams = '';
        $restrictedResources = [
            [
                'method' => $method,
                'path' => $path,
                'dataElements' => $dataElements,
            ]
        ];
        $bodyParam = ['restrictedResources' => $restrictedResources];
        $responseArr = $this->send($uri, $queryParams, $bodyParam, 'POST');
        return $responseArr;
    }

    /**
     * 发送带亚马逊签名的请求
     * @param $uri
     * @param array $queryParams
     * @param array $bodyParam
     * @param string $method
     * @return array
     */
    protected function send($uri, $queryParams = [], $bodyParam = [], $method = 'GET')
    {
        try {
            $datetime = gmdate('Ymd\THis\Z');
            $headers = $headersArr = [];
            $headersArr['host'] = $this->endpoint;
            $headersArr['user-agent'] = self::USER_AGENT;
            $headersArr['x-amz-access-token'] = $this->accessToken;
            $headersArr['x-amz-date'] = $datetime;
            $headersArr['content-type'] = 'application/json';
            if ($this->withSecurityToken) {
                $headersArr['x-amz-security-token'] = $this->sessionToken;
            }
            ksort($headersArr);
            foreach ($headersArr as $key => $value) {
                $headers[] = $key . ': ' . $value;
            }
            ksort($bodyParam);
            $apiUrl = 'https://' . $this->endpoint . $uri;
            if (in_array($method, ['POST', 'PUT', 'PATCH'])) {
                $bodyParam = !empty($bodyParam) ? json_encode($bodyParam) : '';
                $jsonData = $bodyParam;
            } else {
                if (empty($bodyParam)) $bodyParam = '';
                $jsonData = '';
            }
            if (!empty($queryParams)) {
                ksort($queryParams);
                $queryString = http_build_query($queryParams);
                if (!empty($queryString)) $apiUrl .= '?' . $queryString;
            } else {
                $queryString = '';
            }
            $headers[] = 'Authorization: ' . $this->setAuthorization($uri, $queryString, $bodyParam, $method, $datetime);
            $this->curlOption = [];
            $this->curlOption[CURLOPT_CUSTOMREQUEST] = $method;
            $response = $this->curlRequest($apiUrl, $jsonData, $headers, $this->curlOption);
            $data = json_decode($response['data'], true, 512, JSON_BIGINT_AS_STRING);
            $response['data'] = is_array($data) ? $data : $response['data'];
            if (is_string($response['data']) && stripos($response['data'], '<html') !== false) {
                $response['data'] = strip_tags($response['data']);
            }
        } catch (Exception $e) {
            $response = ['http_code' => 400, 'data' => $e->getMessage()];
        }
        return $response;
    }

    /**
     * @param $uri
     * @param $queryString
     * @param $bodyParams
     * @param $method
     * @param $datetime
     * @return string
     */
    protected function setAuthorization($uri, $queryString, $bodyParams, $method, $datetime)
    {
        $shortDate = substr($datetime, 0, 8);
        $service = 'execute-api';
        $signHeader = 'host;user-agent;x-amz-date';
        $paramSign = "$method\n";
        $paramSign .= "$uri\n";
        $paramSign .= "$queryString\n";
        $paramSign .= "host:" . $this->endpoint . "\n";
        $paramSign .= "user-agent:" . self::USER_AGENT . "\n";
        $paramSign .= "x-amz-date:{$datetime}\n";
        $paramSign .= "\n";
        $paramSign .= "$signHeader\n";
        $paramSign .= hash('sha256', $bodyParams);
        $paramSign = hash('sha256', $paramSign);
        $scope = $this->createScope($shortDate, $this->region, $service);
        $signKey = $this->getSignKey($shortDate, $this->region, $service, $this->secretAccessKey);
        $signature = hash_hmac('sha256', sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", $datetime, $scope, $paramSign), $signKey);
        $authorization = sprintf('AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s', $this->accessKeyId, $scope, $signHeader, $signature);
        return $authorization;
    }

    /**
     * @param $shortDate
     * @param $region
     * @param $service
     * @return string
     */
    protected function createScope($shortDate, $region, $service)
    {
        return "$shortDate/$region/$service/aws4_request";
    }

    /**
     * @param $shortDate
     * @param $region
     * @param $service
     * @param $secretKey
     * @return string
     */
    protected function getSignKey($shortDate, $region, $service, $secretKey)
    {
        $signKey = hash_hmac('sha256', 'aws4_request',
            hash_hmac('sha256', $service,
                hash_hmac('sha256', $region,
                    hash_hmac('sha256', $shortDate, 'AWS4' . $secretKey, true),
                    true),
                true),
            true);
        return $signKey;
    }

    /**
     * @param $accessKey
     * @param $secretKey
     * @param string $roleArn
     * @param int $durationSeconds
     * @return array
     */
    protected function getSessionToken($accessKey, $secretKey, $roleArn = 'arn:aws:iam::923441203225:role/spapi', $durationSeconds = 3600)
    {
        try {
            $param = [
                'Action' => 'AssumeRole',
                'DurationSeconds' => $durationSeconds,
                'RoleArn' => $roleArn,
                'RoleSessionName' => 'GG-session',
                'Version' => '2011-06-15'
            ];
            ksort($param);
            $queryParam = http_build_query($param);
            $host = 'sts.amazonaws.com';
            $datetime = gmdate('Ymd\THis\Z');
            $headers = [
                'Content-Type: application/x-www-form-urlencoded; charset=utf-8',
                'Host: ' . $host,
                'X-Amz-Date: ' . $datetime,
            ];
            $headers[] = 'Authorization: ' . $this->setAuthorizationSession($queryParam, $datetime, $host, $accessKey, $secretKey);
            $this->curlOption = [];
            $this->curlOption[CURLOPT_CUSTOMREQUEST] = 'GET';
            $jsonData = [];
            $apiUrl = sprintf('https://%s/?%s', $host, $queryParam);
            $response = $this->curlRequest($apiUrl, $jsonData, $headers, $this->curlOption);
            $res = simplexml_load_string($response['data'], 'SimpleXMLElement', LIBXML_NOCDATA);
            $data = json_decode(json_encode($res), true, 512, JSON_BIGINT_AS_STRING);
            $response['data'] = is_array($data) ? $data : $response['data'];
            if (is_string($response['data']) && stripos($response['data'], '<html') !== false) {
                $response['data'] = strip_tags($response['data']);
            }
        } catch (Exception $e) {
            $response = ['http_code' => 400, 'data' => $e->getMessage()];
        }
        return $response;
    }

    /**
     * @param $queryParam
     * @param $datetime
     * @param $host
     * @param $accessKey
     * @param $secretKey
     * @return string
     */
    protected function setAuthorizationSession($queryParam, $datetime, $host, $accessKey, $secretKey)
    {
        $service = 'sts';
        $shortDate = substr($datetime, 0, 8);
        $queryStr = '';
        $queryStr = hash('sha256', $queryStr);
        $signHeader = 'host;x-amz-date';
        $paramSign = "GET\n";
        $paramSign .= "/\n";
        $paramSign .= "{$queryParam}\n";
        $paramSign .= "host:" . $host . "\n";
        $paramSign .= "x-amz-date:" . $datetime . "\n";
        $paramSign .= "\n";
        $paramSign .= "{$signHeader}\n";
        $paramSign .= $queryStr;
        $paramSign = hash('sha256', $paramSign);
        $scope = $this->createScope($shortDate, $this->region, $service);
        $signature = hash_hmac('sha256', sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", $datetime, $scope, $paramSign), $this->getSignKey($shortDate, $this->region, $service, $secretKey));
        $authorization = sprintf('AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s', $accessKey, $scope, $signHeader, $signature);
        return $authorization;
    }

    /**
     * @param $url
     * @param string $data
     * @param array $header
     * @param array $option
     * @param int $timeout
     * @return array
     */
    protected function curlRequest($url, $data = '', $header = [], $option = [], $timeout = 300)
    {
        $opts = [];
        $opts[CURLOPT_URL] = $url;
        $opts[CURLOPT_HEADER] = 0;
        $opts[CURLOPT_HTTPHEADER] = $header;
        $opts[CURLOPT_RETURNTRANSFER] = 1;
        if (!empty($data)) {
            if (isset($option[CURLOPT_CUSTOMREQUEST]) && $option[CURLOPT_CUSTOMREQUEST] === 'POST') {
                $opts[CURLOPT_POST] = 1;
            }
            $opts[CURLOPT_POSTFIELDS] = is_string($data) ? $data : http_build_query($data);
        }
        $opts[CURLOPT_TIMEOUT] = $timeout;
        $opts[CURLOPT_SSL_VERIFYPEER] = 0;
        $opts[CURLOPT_SSL_VERIFYHOST] = 0;
        $opts += $option;
        $ch = curl_init();
        curl_setopt_array($ch, $opts);
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $errno = curl_errno($ch);
        if (0 !== $errno) {
            $response = sprintf('[%s]: %s', $errno, curl_error($ch));
        }
        curl_close($ch);
        return array('http_code' => $http_code, 'data' => $response);
    }

}