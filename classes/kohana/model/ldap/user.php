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
	 * @return Model_Ldap_User
	 */
	public function get ( $username )
	{
		$config = $this->_database->config();

		$query = array (
			'filter' => $this->_database->format_filter($config['search']['user']['filter'], array('u' => $username)),
			'basedn' => $config['search']['user']['basedn'],
			'scope'  => $config['search']['user']['scope'],
			'attributes' => $config['mapping']['user']
		);

		$result = $this->_database->query(Database::SELECT, $query);

		if (is_array($result))
		{
			$keys = array_keys($result);
			$ldapdata = $result[$keys[0]];

			$data = array(
				'_dn' => $ldapdata['dn'],
				'_type' => 'ldap'
			);
			foreach ($query['attributes'] as $var => $attr)
			{
				if (isset($ldapdata[$attr]))
				{
					$data[$var] = $ldapdata[$attr];
				}
			}

			$user = new self();
			return $user->database($this->_database)->data($data);
		}

		return FALSE;
	}

} // End Model_Ldap_User

