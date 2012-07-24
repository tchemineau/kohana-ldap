<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * LDAP Auth driver.
 * [!!] this Auth driver does not support roles nor autologin.
 *
 * @package	Kohana/Auth-LDAP
 * @author	 Thomas Chemineau - thomas.chemineau@gmail.com
 * @copyright  (c) 2007-2012 Kohana Team
 * @license	http://kohanaframework.org/license
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
			if (!is_null($config))
			{
				// Do not considere an LDAP server if its search user config is not found
				if (!isset($config['search']) || !isset($config['search']['user']))
				{
					continue;
				}

				// Default values
				if (!isset($config['search']['user']['filter']))
				{
					$config['search']['user']['filter'] = '(&(objectClass=person)(uid=%u))';
				}
				if (!isset($config['search']['user']['basedn']))
				{
					$config['search']['user']['basedn'] = 'ou=people,dc=example,dc=org';
				}
				if (!isset($config['search']['user']['scope']))
				{
					$config['search']['user']['scope'] = 'one';
				}
				if (!isset($config['mapping']))
				{
					$config['mapping'] = array();
				}
				if (!isset($config['mapping']['user']))
				{
					$config['search']['user']['filter'] = array();
				}

				// Store config
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
			$ldapquery = array (
				'filter' => $ldapdb->format_filter($config['search']['user']['filter'], array('u' => $username)),
				'basedn' => $config['search']['user']['basedn'],
				'scope'  => $config['search']['user']['scope'],
				'attributes' => $config['mapping']['user']
			);
			$ldapresult = $ldapdb->query(Database::SELECT, $ldapquery);

			if (is_array($ldapresult))
			{
				$keys = array_keys($ldapresult);
				$ldapuser = $ldapresult[$keys[0]];

				if ($ldapdb->bind($ldapuser['dn'], $password))
				{
					$user = array();
					foreach ($ldapquery['attributes'] as $var => $attr)
					{
						if (isset($ldapuser[$attr]))
						{
							$user[$var] = $ldapuser[$attr];
						}
					}
					return $this->complete_login($user);
				}
			}
		}

		return FALSE;
	}

} // End Auth LDAP

