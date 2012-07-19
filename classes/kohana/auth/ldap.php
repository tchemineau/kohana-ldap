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
		if (!isset($this->_config['ldap']) && !isset($this->_config['ldap']['server']))
		{
			return FALSE;
		}

		if (!isset($this->_config['ldap']['order']))
		{
			$this->_config['ldap']['order'] = array('default');
		}
		if (!is_array($this->_config['ldap']['order']))
		{
			$this->_config['ldap']['order'] = array($this->_config['ldap']['order']);
		}

		foreach ($this->_config['ldap']['order'] as $serverid)
		{
			if (!isset($this->_config['ldap']['server'][$serverid]))
			{
				continue;
			}

			$config = $this->_config['ldap']['server'][$serverid] + array('type' => 'ldap');
			$ldapdb = Database::instance($serverid, $config);

			$query = array(
				'filter' => $ldapdb->format_filter(
					isset($config['filter']) ? $config['filter'] : '(&(objectClass=person)(uid=%u))',
					array('u' => $username)
				),
				'basedn' => isset($config['basedn']) ? $config['basedn'] : 'ou=people,dc=example,dc=org',
				'scope'  => isset($config['scope']) ? $config['scope'] : 'one',
				'attributes' => isset($config['mapping']) && isset($config['mapping']['user']) ? $config['mapping']['user'] : array()
			);

			$result = $ldapdb->query(Database::SELECT, $query);

			if (is_array($result))
			{
				$keys = array_keys($result);
				$ldapuser = $result[$keys[0]];

				if ($ldapdb->bind($ldapuser['dn'], $password))
				{
					$user = array();
					foreach ($query['attributes'] as $var => $attr)
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

