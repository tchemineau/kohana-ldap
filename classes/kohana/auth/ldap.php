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
	 * Format a filter.
	 *
	 * @param   string   $filter   A LDAP filter
	 * @param   array    $vars     Variables to replace
	 * @return  string
	 */
	public static function format_filter ( $filter, $vars )
	{
		foreach ($vars as $var => $val)
		{
			$filter = preg_replace('/\%'.$var.'/', $val, $filter);
		}
		return $filter;
	}

	/**
	 * Get the logged in user or return $default if a user is not found
	 *
	 * @param   mixed   default
	 * @return  string
	 */
	public function get_user ( $default = NULL )
	{
		return null;
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
	 * Ldap link.
	 */
	private $_ldapLink = null;

	/**
	 * Connect to the LDAP directory.
	 *
	 * @param   array   $config   Parameters to connect to a LDAP server
	 * @return  boolean
	 */
	protected function _connect ( $config )
	{
		if ($this->_ldapLink)
		{
			return TRUE;
		}
		if (!isset($config['uri']))
		{
			return FALSE;
		}
		if (isset($config['ssl']) && $config['ssl'])
		{
			$this->_ldapLink = @ldap_connect($config['uri']);
			if ($this->_ldapLink && !@ldap_start_tls($this->_ldapLink))
			{
				$this->disconnect();
				$uri = 'ldaps://' . preg_replace('#ldaps?://#', '', $config['uri']);
				if (preg_match('/:[0-9]+/', $uri) == 0)
				{
					$config['uri'] = ':636';
				}
			}
		}
		if (!$this->_ldapLink)
		{
			$this->_ldapLink = @ldap_connect($config['uri']);
		}
		if ($this->_ldapLink === false)
		{
			return FALSE;
		}
		if (!isset($config['version']))
		{
			$config['version'] = 3;
		}
		if ($config['version'] == 3)
		{
			ldap_set_option($this->_ldapLink, LDAP_OPT_PROTOCOL_VERSION, 3) ;
		}
		if (isset($config['binddn']) && isset($config['bindpw']))
		{
			$binddn = is_null($config['binddn']) ? '' : $config['binddn'];
			$bindpw = is_null($config['bindpw']) ? '' : $config['bindpw'];
			if (strlen($binddn) > 0 && strlen($bindpw) > 0 && !@ldap_bind($this->_ldapLink, $binddn, $bindpw))
			{
				return FALSE;
			}
		}
		else if (!@ldap_bind($this->_ldapLink))
		{
			return FALSE;
		}
		return TRUE;
	}

	/**
	 * Close this Ldap connection.
	 *
	 * @return boolean
	 */
	protected function _disconnect ()
	{
		if ($this->_ldapLink)
		{
			ldap_close($this->_ldapLink);
			$this->_ldapLink = NULL;
			return TRUE;
		}
		return FALSE;
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

			$server = $this->_config['ldap']['server'][$serverid];

			if (!$this->_connect($server))
			{
				continue;
			}

			if (!isset($server['filter']))
			{
				$server['filter'] = '(&(objectClass=person)(uid=%u))';
			}
			if (!isset($server['basedn']))
			{
				$server['basedn'] = 'ou=people,dc=example,dc=org';
			}
			if (!isset($server['scope']))
			{
				$server['scope'] = 'one';
			}

			$filter = self::format_filter($server['filter'], array('u' => $username));
			$dns = $this->_search_dn($filter, $server['basedn'], $server['scope']);

			if (is_array($dns))
			{
				$dn = $dns[0];

				if (@ldap_bind($this->_ldapLink, $dn, $password))
				{
					return $this->complete_login($username);
				}
			}
		}

		return FALSE;
	}

	/**
	 * Search for LDAP entries.
	 *
	 * @param   string   $filter    LDAP filter
	 * @param   string   $basedn    LDAP base dn
	 * @param   string   $scope     Search scope (base, one or sub)
	 * @param   array    $attrs     Attributes to return
	 * @return  array|false
	 */
	protected function _search ( $filter, $basedn, $scope = 'one', $attrs = array() )
	{
		if (!$this->_ldapLink)
		{
			return FALSE;
		}

		if (sizeof($attrs) == 0)
		{
			$attrs = array( 'dn' );
		}

		switch ($scope)
		{
			case 'base':
				$search_result = @ldap_read($this->_ldapLink, $basedn, $filter, $attrs);
				break;
			case 'one':
				$search_result = @ldap_list($this->_ldapLink, $basedn, $filter, $attrs);
				break;
			case 'sub':
				$search_result = @ldap_search($this->_ldapLink, $basedn, $filter, $attrs);
			default:
				return false;
		}

		if (!$search_result)
		{
			return FALSE;
		}

		$entries = @ldap_get_entries($this->_ldapLink, $search_result);
		if (is_array($entries) && sizeof($entries) > 0)
		{
		   return $entries;
		}

		return FALSE;
	}

	/**
	 * Search an entry and return its DN.
	 *
	 * @param   string   $filter   A LDAP filter
	 * @param   string   $basedn   LDAP base dn
	 * @param   string   $scope    Search scope (base, one or sub)
	 * @return  string|false
	 */
	protected function _search_dn ( $filter, $basedn, $scope = 'one' )
	{
		if (!$this->_ldapLink)
		{
			return FALSE;
		}

		$entries = $this->_search($filter, $basedn, $scope);
		if (is_array($entries))
		{
			$entriesb = array();
			foreach ($entries as $index => $values)
			{
				if (is_array($values) && !is_null($values['dn']))
				{
					$entriesb[] = $values['dn'];
				}
			}
			return $entriesb ;
		}

		return FALSE;
	}

} // End Auth LDAP

