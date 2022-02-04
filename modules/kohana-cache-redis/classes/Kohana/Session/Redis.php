<?php defined('SYSPATH') or die('No direct script access.');

use \Firebase\JWT\JWT;

/**
 * Redis hash session handler
 *
 * @package Redis
 * @author Mutant Industries ltd. <mutant-industries@hotmail.com>
 */
class Kohana_Session_Redis extends Session {

    /**
     * @var Redis_Client
     */
    protected $_client;

    /**
     * @var string
     */
    protected $_session_key_namespace;

    /**
     * @var String
     */
    protected $_session_id;

    /**
     * @var array
     */
    protected $_changed = array();

    /**
     * @var bool
     */
    protected $_loaded = FALSE;

    /**
     * @var bool
     */
    protected $_lazy;

    /**
     * @param array $config
     * @param string $id
     * @throws Session_Exception
     */
    public function __construct(array $config = NULL, $id = NULL)
    {
        $this->_lazy = $config['lazy'];
        $this->_secret = $config['secret'];
        $this->_session_key_namespace = $config['session_key_namespace'];

        try
        {
            $this->_client = Cache::instance('redis');
        }
        catch (Redis_Exception $e)
        {
            throw new Session_Exception('Unable to instantiate redis client: ' . $e->getMessage() . " on ". $e->getFile(). ":". $e->getLine(), null, 0, $e);
        }

        parent::__construct($config, $id);
    }

    /**
     * Session object is rendered to a serialized string. If encryption is
     * enabled, the session will be encrypted. If not, the output string will
     * be encoded.
     *
     *     echo $session;
     *
     * @return  string
     * @uses    Encrypt::encode
     */
    public function __toString()
    {
        $this->_loaded || $this->as_array();

        return parent::__toString();
    }

    /**
     * Returns the current session array. The returned array can also be
     * assigned by reference.
     *
     *     // Get a copy of the current session data
     *     $data = $session->as_array();
     *
     *     // Assign by reference for modification
     *     $data =& $session->as_array();
     *
     * @return  array
     */
    public function & as_array()
    {
        if ( ! $this->_loaded)
        {
            $data = $this->_client->get($this->_session_key_namespace . $this->_session_id);
            if(is_null($data)) 
                $data = array();

            $this->_data = Arr::merge(Arr::map('unserialize', $data), $this->_changed);

            $this->_loaded = TRUE;
        }

        return $this->_data;
    }

    /**
     * Get the current session id, if the session supports it.
     *
     *     $id = $session->id();
     *
     * @return  string
     */
    public function id()
    {
        return $this->_session_id;
    }

    /**
     * Get a variable from the session array.
     *
     *     $foo = $session->get('foo');
     *
     * @param   string  $key        variable name
     * @param   mixed   $default    default value to return
     * @return  mixed
     */
    public function get($key, $default = NULL)
    {
        if (array_key_exists($key, $this->_data))
        {
            return $this->_data[$key] === NULL ? $default : $this->_data[$key];
        }
        return $default;
    }

    /**
     * Get and delete a variable from the session array.
     *
     *     $bar = $session->get_once('bar');
     *
     * @param   string  $key        variable name
     * @param   mixed   $default    default value to return
     * @return  mixed
     */
    public function get_once($key, $default = NULL)
    {
        $value = $this->get($key, $default);

        $this->_data[$key] = $this->_changed[$key] = NULL;

        return $value;
    }

    /**
     * Set a variable in the session array.
     *
     *     $session->set('foo', 'bar');
     *
     * @param   string  $key    variable name
     * @param   mixed   $value  value
     * @return  $this
     */
    public function set($key, $value)
    {
        if ( ! array_key_exists($key, $this->_data) || $this->_data[$key] !== $value)
        {
            $this->_changed[$key] = $value;
        }

        $this->_data[$key] = $value;

        return $this;
    }

    /**
     * Set a variable by reference.
     *
     *     $session->bind('foo', $foo);
     *
     * @param   string  $key    variable name
     * @param   mixed   $value  referenced value
     * @return  $this
     */
    public function bind($key, & $value)
    {
        $this->_data[$key] = & $value;
        $this->_changed[$key] = & $value;

        return $this;
    }

    /**
     * Removes a variable in the session array.
     *
     *     $session->delete('foo');
     *
     * @param   string  $key,...    variable name
     * @return  $this
     */
    public function delete($key)
    {
        $args = func_get_args();

        foreach ($args as $key)
        {
            $this->set($key, NULL);
        }

        return $this;
    }

    /**
     * Loads the raw session data string and returns it.
     *
     * @param   string $id session id
     * @return  mixed
     */
    protected function _read($id = NULL)
    {
        if ($id)
        {
            if ($this->_client->exists($this->_session_key_namespace . $id))
            {
                // Set the current session id
                $this->_session_id = $id;

                // session found
                return $this->_lazy ? array() : $this->as_array();
            }
        }

        // Create a new session id
        $this->_regenerate();

        return NULL;
    }

    /**
     * Generate a new session id and return it.
     *
     * @return  string
     */
    protected function _regenerate()
    {
        do
        {
            // Create a new session id
            $id = substr_replace(substr_replace(str_replace('.', '', uniqid(NULL, TRUE)), ':', 4, 0), ':', 7, 0);
        }
        while ($this->_client->exists($this->_session_key_namespace . $id));

        return $this->_session_id = $id;
    }

    /**
     * Writes the current session.
     *
     * @return  boolean
     */
    protected function _write()
    {
        if ( null !== $this->_id_token )
        {
            return TRUE;
        }

        if ( null === $this->_session_id )
        {
            // Create a new session id
            $this->_regenerate();
        }

        $data = Helper::getJwtDataForUser(Arr::get($this->_data, 'user'), Arr::get($this->_data, 'associate'));
        $data[Constants::SESSION_KEY_IMPERSONATION] = null;
		if(array_key_exists(Constants::SESSION_KEY_IMPERSONATION, $this->_data))
			$data[Constants::SESSION_KEY_IMPERSONATION] = Arr::get($this->_data, Constants::SESSION_KEY_IMPERSONATION);
		
		$payload = array();
        $payload['iat'] = $this->_data['last_active'];
        $payload['exp'] = $payload['iat'] + $this->_lifetime;
        $payload['ip'] = $_SERVER['REMOTE_ADDR'];
		$payload['jti'] = $this->_session_id;
		$payload['data'] = $data;
        
        $this->_id_token = JWT::encode($payload, $this->_secret);

        $this->_changed['last_active'] = time();

        $this->_client->set($this->_session_key_namespace . $this->_session_id, $this->as_array(), $this->_lifetime);

        return TRUE;
    }

    /**
     * Return JWT associate with current session
     *
     * @return  string
     */
    public function getIdToken()
    {
        return $this->_id_token;
    }

    /**
     * Destroys the current session.
     *
     * @return  boolean
     */
    protected function _destroy()
    {
        $this->_client->delete($this->_session_key_namespace . $this->_session_id);

        return TRUE;
    }

    /**
     * Restarts the current session.
     *
     * @return  boolean
     */
    protected function _restart()
    {
        $this->_regenerate();

        return TRUE;
    }

}
