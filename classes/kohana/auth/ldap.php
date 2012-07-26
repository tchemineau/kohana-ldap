<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * LDAP auth driver.
 * This auth driver does not support roles nor autologin.
 *
 * @package   Kohana/LDAP
 * @author    Thomas Chemineau - thomas.chemineau@gmail.com
 * @copyright (c) 2007-2012 Thomas Chemineau
 * @copyright (c) 2007-2012 Kohana Team
 * @license   http://kohanaframework.org/license
 */
class Kohana_Auth_Ldap extends Auth
{

	/**
	 * LDAP database parameters.
	 */
	private $_ldap = array ();

	/**
	 * Loads LDAP configuration parameter from database config.
	 *
	 * @param   array   $config   LDAP auth configuration
	 * @return  void
	 */
	public function __construct ( $config = array() )
	{
		parent::__construct($config);

		// Set default values.
		if (!isset($this->_config['ldap']))
		{
			$this->_config['ldap'] = array ();
		}
		if (!isset($this->_config['ldap']['order']))
		{
			$this->_config['ldap']['order'] = array('default');
		}
		if (!is_array($this->_config['ldap']['order']))
		{
			$this->_config['ldap']['order'] = array($this->_config['ldap']['order']);
		}

		// Get LDAP database and store configuration
		foreach ($this->_config['ldap']['order'] as $ldap)
		{
			$config = Kohana::$config->load('database')->get($ldap);
			if (!is_null($config) && isset($config['type']) && strcasecmp('ldap', $config['type']) == 0)
			{
				$this->_ldap[$ldap] = $config;
			}
		}
	}

	/**
	 * Most of the time, it is not possible to retrieve a password
	 * from a user into a LDAP directory.
	 *
	 * @param   string  $password
	 * @return  boolean
	 */
	public function check_password ( $password )
	{
		return FALSE;
	}

	/**
	 * Check to see if the user is logged in, and if $role is set,
	 * has all roles.
	 *
	 * @param   mixed   $role
	 * @return  boolean
	 */
	public function logged_in ( $role = NULL )
	{
		return false;
	}

	/**
	 * Most of the time, it is not possible to retrieve a password
	 * from a user into a LDAP directory.
	 *
	 * @param   mixed   username
	 * @return  null
	 */
	public function password ( $username )
	{
		return null;
	}

	/**
	 * Authenticate a user against an LDAP directory.
	 *
	 * @param   string   $username
	 * @param   string   $password
	 * @param   boolean  $remember   Enable autologin (not supported)
	 * @return  boolean
	 */
	protected function _login ( $username, $password, $remember )
	{
		foreach ($this->_ldap as $serverid => $config)
		{
			$ldapdb = Database::instance($serverid, $config);
			$ldapuser = Model::factory('Ldap_User')
				->database($ldapdb)
				->get($username);

			if ($ldapuser && $ldapuser->authenticate($password))
			{
				return $this->complete_login($ldapuser->data());
			}
		}

		return FALSE;
	}

} // End Auth LDAP

