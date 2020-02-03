<?php
namespace Yuca\SSO;

use GuzzleHttp\Client as GuzzleHttp;

/**
 * Single sign-on broker.
 *
 * The broker lives on the website visited by the user. The broken doesn't have any user credentials stored. Instead it
 * will talk to the SSO server in name of the user, verifying credentials and getting user information.
 */
class Client
{
    /**
     * Version of SSO Broker
     * @var string
     */
    protected $version = 'v1';

    /**
     * Url of SSO server
     * @var string
     */
    protected $url;

    /**
     * My identifier, given by SSO provider.
     * @var string
     */
    public $broker;

    /**
     * My secret word, given by SSO provider.
     * @var string
     */
    protected $secret;

    /**
     * Session token of the client
     * @var string
     */
    public $token;

    /**
     * User info recieved from the server.
     * @var array
     */
    protected $userInfo;

    /**
     * Cookie lifetime
     * @var int
     */
    protected $cookieLifetime;

    /**
     * Class constructor
     *
     * @param string $url    Url of SSO server
     * @param string $broker My identifier, given by SSO provider.
     * @param string $secret My secret word, given by SSO provider.
     */
    public function __construct($url, $broker, $secret, $cookieLifetime = 3600)
    {
        if (!$url) throw new \InvalidArgumentException("SSO server URL not specified");
        if (!$broker) throw new \InvalidArgumentException("SSO broker id not specified");
        if (!$secret) throw new \InvalidArgumentException("SSO broker secret not specified");

        $this->url = $url;
        $this->broker = $broker;
        $this->secret = $secret;
        $this->cookieLifetime = $cookieLifetime;

        if (isset($_COOKIE[$this->getCookieName()])) {
            $this->token = $_COOKIE[$this->getCookieName()];
        }
    }

    /**
     * Get the cookie name.
     *
     * Note: Using the broker name in the cookie name.
     * This resolves issues when multiple brokers are on the same domain.
     *
     * @return string
     */
    protected function getCookieName()
    {
        return "sso_{$this->version}_token_" . preg_replace('/[_\W]+/', '_', strtolower($this->broker));
    }

    /**
     * Generate session id from session key
     *
     * @return string
     */
    protected function getSessionId()
    {
        if (!isset($this->token)) return null;

        $checksum = hash('sha256', 'session' . $this->token . $this->secret);
        return "SSO-{$this->broker}-{$this->token}-$checksum";
    }

    /**
     * Generate session token
     */
    public function generateToken()
    {
        if (isset($this->token)) return;

        $this->token = base_convert(md5(uniqid(rand(), true)), 16, 36);
        setcookie($this->getCookieName(), $this->token, time() + $this->cookieLifetime, '/');
    }

    /**
     * Clears session token
     */
    public function clearToken()
    {
        setcookie($this->getCookieName(), null, 1, '/');
        $this->token = null;
    }

    /**
     * Check if we have an SSO token.
     *
     * @return boolean
     */
    public function isAttached()
    {
        return isset($this->token);
    }

    /**
     * Get URL to attach session at SSO server.
     *
     * @return string
     */
    public function getAttachUrl()
    {
        $this->generateToken();

        $protocol = !empty($_SERVER['HTTPS']) ? 'https://' : 'http://';
        $returnUrl = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        $data = [
            'command' => 'attach',
            'broker' => $this->broker,
            'token' => $this->token,
            'checksum' => hash('sha256', 'attach' . $this->token . $this->secret),
            'return_url' => $returnUrl,
        ];

        return $this->url . "?" . http_build_query($data);
    }

    /**
     * Attach our session to the user's session on the SSO server.
     *
     * @return array|boolean
     */
    public function attach()
    {
        if ($this->isAttached()) {
            return true;
        }

        header('Location:' . $this->getAttachUrl());
        die;
    }

    /**
     * Get the request url for a command
     *
     * @param string $command
     * @param array  $params   Query parameters
     * @return string
     */
    protected function getRequestUrl($command, $params = [])
    {
        $params['command'] = $command;
        return $this->url . '?' . http_build_query($params);
    }

    /**
     * Execute on SSO server.
     *
     * @param string       $method  HTTP method: 'GET', 'POST', 'DELETE'
     * @param string       $command Command
     * @param array|string $data    Query or post parameters
     * @return array|object
     */
    protected function request($method, $command, $data = null)
    {
        if (!$this->isAttached()) {
            throw new \Exception('No token');
        }

        if ($data && is_string($data)) {
            $key = $data;
            $data = [];
            $data[$key] = 1;
        }

        // Set Authorization using token
        $data['access_token'] = $this->getSessionId();
        $data['referer_url'] = (!empty($_SERVER['HTTPS']) ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        $url = $this->getRequestUrl($command, !$data || $method === 'POST' ? [] : $data);

        $client = new GuzzleHttp(['http_errors' => false]);

        if ($method === 'POST' && !empty($data)) {
            $response = $client->post($url, ['form_params' => $data]);
        } else {
            $response = $client->{strtolower($method)}($url);
        }

        $httpCode = $response->getStatusCode();
        $contents = $response->getBody()->getContents();
        $result = json_decode($contents, true);
        if ($httpCode == 200) {
            return $result;
        } elseif ($httpCode == 307) {
            header("Location: " . $result['error']);
            die;
        } else {
            if ($httpCode == 403) {
                $this->clearToken();
            }
            throw new \Exception($contents, $httpCode);
        }
    }

    /**
     * Log the client in at the SSO server.
     *
     * Only brokers marked trused can collect and send the user's credentials. Other brokers should omit $username and
     * $password.
     *
     * @param string $username
     * @param string $password
     * @return array  user info
     * @throws Exception if login fails eg due to incorrect credentials
     */
    public function login($username = null, $password = null)
    {
        if (!isset($username) && isset($_POST['username'])) $username = $_POST['username'];
        if (!isset($password) && isset($_POST['password'])) $password = $_POST['password'];

        $result = $this->request('POST', 'login', compact('username', 'password'));
        $this->userInfo = $result;

        return $this->userInfo;
    }

    /**
     * Logout at sso server.
     */
    public function logout()
    {
        // Send logout request
        $this->request('POST', 'logout', 'logout');
    }

    /**
     * Get user information.
     *
     * @return object|null
     */
    public function getUserInfo()
    {
        if (empty($this->userInfo)) {
            $this->userInfo = $this->request('GET', 'userInfo');
        }

        return $this->userInfo;
    }

    /**
     * Magic method to do arbitrary request
     *
     * @param string $fn
     * @param array  $args
     * @return mixed
     */
    public function __call($fn, $args)
    {
        $sentence = strtolower(preg_replace('/([a-z0-9])([A-Z])/', '$1 $2', $fn));
        $parts = explode(' ', $sentence);

        $method = count($parts) > 1 && in_array(strtoupper($parts[0]), ['GET', 'DELETE'])
            ? strtoupper(array_shift($parts))
            : 'POST';
        $command = join('-', $parts);

        return $this->request($method, $command, $args);
    }
}