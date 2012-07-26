<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * LDAP user model.
 *
 * @package   Kohana/LDAP
 * @author    Thomas Chemineau - thomas.chemineau@gmail.com
 * @copyright (c) 2012 Thomas Chemineau
 * @license   http://kohanaframework.org/license
 */
class Kohana_Model_Ldap_User extends Model
{

	/**
	 * LDAP user data.
	 *
	 * @var array
	 */
	private $_data = null;

	/**
	 * LDAP database instance.
	 *
	 * @var Database
	 */
	private $_database = null;

	/**
	 * Authenticate a user against an LDAP directory.
	 *
	 * @param   string   $password
	 * @return  boolean
	 */
	public function authenticate ( $password )
	{
		if (is_null($this->_data) || !isset($this->_data['_dn']))
		{
			return FALSE;
		}

		return $this->_database->bind($this->_data['_dn'], $password);
	}

	/**
	 * Return user data attributes from LDAP directory.
	 *
	 * @param   array   $attributes
	 * @return  array
	 * @return  false
	 */
	public function attribute ( $attributes )
	{
		if (is_null($this->_database))
		{
			return FALSE;
		}
		if (!is_null($attributes) && !is_array($attributes))
		{
			$attributes = array($attributes);
		}
		if (sizeof($attributes) == 0)
		{
			return array();
		}

		$result = $this->_database->query(
			Database::SELECT,
			array (
				'filter' => '(objectClass=top)',
				'basedn' => $this->_data['_dn'],
				'scope'  => 'base',
				'attributes' => $attributes
			)
		);

		if (is_array($result))
		{
			return $this->parse_result($result, $attributes);
		}

		return FALSE;
	}

	/**
	 * Get or set user data.
	 *
	 * @param   array   $data
	 * @return  array
	 */
	public function data ( $data = null )
	{
		if (is_null($data))
		{
			return $this->_data;
		}
		if (isset($data['_type']) && strcasecmp($data['_type'], 'ldap') == 0)
		{
			if (is_null($this->_database) && isset($data['_name']))
			{
				$this->_database = Database::instance($data['_name']);
			}
		}
		$this->_data = $data;
		return $this;
	}

	/**
	 * Get or set database instance.
	 *
	 * @param   Database   $database
	 * @return  Database
	 * @return  Model_Ldap_User
	 */
	public function database ( $database = null )
	{
		if (is_null($database))
		{
			return $this->_database;
		}
		$this->_database = $database;
		return $this;
	}

	/**
	 * Get a user from its username.
	 *
	 * @param  string   $username
	 * @param  boolean  $dn
	 * @return Model_Ldap_User
	 */
	public function get ( $username, $dn = false )
	{
		$config = $this->_database->get_config();

		if ($dn)
		{
			$query = array (
				'filter' => '(objectClass=top)',
				'basedn' => $username,
				'scope'  => 'base',
				'attributes' => $config['mapping']['user']
			);
		}
		else
		{
			$filter = $this->_database->format_filter(
				$config['search']['user']['filter'],
				array('u' => $username)
			);
			$query = array (
				'filter' => $filter,
				'basedn' => $config['search']['user']['basedn'],
				'scope'  => $config['search']['user']['scope'],
				'attributes' => $config['mapping']['user']
			);
		}

		$result = $this->_database->query(Database::SELECT, $query);

		if (is_array($result))
		{
			$data = $this->parse_result($result, $query['attributes']);
			$user = new self();
			return $user->database($this->_database)->data($data);
		}

		return FALSE;
	}

	/**
	 * Parse result.
	 *
	 * @param   array   result
	 * @return  array
	 */
	public function parse_result ( $result, $attributes )
	{
		$keys = array_keys($result);
		$ldapdata = $result[$keys[0]];

		$data = array(
			'_dn' => $ldapdata['dn'],
			'_type' => 'ldap',
			'_name' => $this->_database->get_name()
		);

		foreach ($attributes as $var => $attr)
		{
			if (!isset($ldapdata[$attr]))
			{
				continue;
			}
			if (is_numeric($var))
			{
				$data[$attr] = $ldapdata[$attr];
			}
			else
			{
				$data[$var] = $ldapdata[$attr];
			}
		}

		return $data;
	}

} // End Model_Ldap_User

