<?php

namespace ramilexe\WowzaSecureToken;

class WowzaSecureToken
{
    /**
     * SHA-256 algorithm
     */
    const SHA256 = 1;

    /**
     * SHA-384 algorithm
     */
    const SHA384 = 2;

    /**
     * SHA-512 algorithm
     */
    const SHA512 = 3;

    /**
     * Constant mapping to string values for php hash function
     * @var array
     */
    protected $algorithms = array(
        self::SHA256 => 'sha256',
        self::SHA384 => 'sha384',
        self::SHA512 => 'sha512',
    );

    /**
     * @var string|null client IP for validation in Wowza
     */
    protected $clientIp = null;

    /**
     * @var string prefix for all query parameters
     */
    protected $prefix;

    /**
     * @var string secret key
     */
    protected $sharedSecret;

    public function __construct()
    {

    }

    /**
     * Set client IP for using in hash
     *
     * @param string $ip
     * @throws WowzaException
     */
    public function setClientIp($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new WowzaException("User IP (" . $ip . ") is invalid");
        }

        $this->clientIp = $ip;
    }

    /**
     * @return null|string
     */
    public function getClientIp()
    {
        return $this->clientIp;
    }

    /**
     * Set shared secret key
     *
     * @param $secret string
     * @throws WowzaException
     */
    public function setSharedSecret($secret)
    {
        $pattern = '|^[\w\d]+$|';
        if (!preg_match($pattern, $secret)) {
            throw new WowzaException("Secret (" . $secret . ") is invalid");
        }

        $this->sharedSecret = $secret;
    }

    public function getSharedSecret()
    {
        return $this->sharedSecret;
    }

    /**
     * Set prefix. The prefix value can only have the following characters that are safe to use in URLs:
     * alphanumeric characters (a - z, A - Z, 0 - 9), percent sign (%), period (.), underscore (_),
     * tilde (~), and hyphen (-).
     *
     * @param $prefix
     * @throws WowzaException
     */
    public function setPrefix($prefix)
    {
        $pattern = '|^[\w\d%\._\-~]+$|';
        if (!preg_match($pattern, $prefix)) {
            throw new WowzaException("Prefix (" . $prefix . ") is invalid");
        }

        $this->prefix = $prefix;
    }

    public function getPrefix()
    {
        return $this->prefix;
    }

    public function getHash($contentUrl, $hashMethod, $params = array())
    {
        if (!$this->sharedSecret) {
            throw new WowzaException("SharedSecret is not set");
        }

        if (!isset($this->algorithms[$hashMethod])) {
            throw new WowzaException("Algorithm " . $hashMethod . " not defined");
        }

        foreach ($params as $key => $param) {
            if ($this->prefix) {
                if (strpos($param, $this->prefix) === false) {
                    $params[$key] = $this->prefix . $params;
                }
            }
        }

        //add client ip
        if ($this->clientIp) {
            $params[$this->clientIp] = "";
        }

        //add secret key
        $params[$this->sharedSecret] = "";

        //sort array
        ksort($params);

        $query = http_build_query($params);

        $urlInfo = parse_url($contentUrl);
        if (!isset($urlInfo['path'])) {
            throw new WowzaException("Invalid url supplied");
        }
        $path = ltrim($urlInfo['path'], '/');
        $pathItems = explode('/', $path);

        if (count($pathItems) < 2) {
            throw new WowzaException("Application or stream is invalid");
        }

        $query = $pathItems[0] . "/" . $pathItems[1] . "?" . $query;

        $hash = hash($this->algorithms[$hashMethod], $query, true);
        $hash = base64_encode($hash);

        return $hash;
    }
}