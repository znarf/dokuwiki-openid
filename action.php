<?php

/**
 * DokuWiki OpenID plugin
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     This version by François Hodierne (http://h6e.net/)
 * @author     Original by Andreas Gohr <andi@splitbrain.org>
 * @version    2.2.0
 */

/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, 
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * The license for this software can likely be found here: 
 * http://www.gnu.org/licenses/gpl-2.0.html
 */

/**
 * This program also use the PHP OpenID library by JanRain, Inc.
 * which is licensed under the Apache license 2.0:
 * http://www.apache.org/licenses/LICENSE-2.0
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

if(!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN',DOKU_INC.'lib/plugins/');

require_once(DOKU_PLUGIN.'action.php');

class action_plugin_openid extends DokuWiki_Action_Plugin {

	/**
	 * Return some info
	 */
	function getInfo()
	{
		return array(
			'author' => 'h6e.net',
			'email'  => 'contact@h6e.net',
			'date'   => '2011-02-15',
			'name'   => 'OpenID plugin',
			'desc'   => 'Authenticate on a DokuWiki with OpenID',
			'url'    => 'http://h6e.net/dokuwiki/plugins/openid',
		);
	}

	/**
	 * Register the eventhandlers
	 */
	function register(&$controller)
	{
		$controller->register_hook('HTML_LOGINFORM_OUTPUT',
			'BEFORE',
			$this,
			'handle_login_form',
			array());
		$controller->register_hook('HTML_UPDATEPROFILEFORM_OUTPUT',
			'AFTER',
			$this,
			'handle_profile_form',
			array());
		$controller->register_hook('ACTION_ACT_PREPROCESS',
			'BEFORE',
			$this,
			'handle_act_preprocess',
			array());
		$controller->register_hook('TPL_ACT_UNKNOWN',
			'BEFORE',
			$this,
			'handle_act_unknown',
			array());
		$controller->register_hook('ACTION_ACT_PREPROCESS',
			'AFTER',
			$this,
			'assigngroup');
	}

	/**
	 * Returns the Consumer URL
	 */
	function _self($do)
	{
		global $ID;
		return wl($ID, 'do=' . $do, true, '&');
	}

	/**
	 * Redirect the user
	 */
	function _redirect($url)
	{
		header('Location: ' . $url);
		exit; 
	}

	/**
	 * Return an OpenID Consumer
	 */
	function getConsumer()
	{
		global $conf;
		if (isset($this->consumer)) {
			return $this->consumer;
		}
		define('Auth_OpenID_RAND_SOURCE', null);
		set_include_path( get_include_path() . PATH_SEPARATOR . dirname(__FILE__) );
		require_once "Auth/OpenID/Consumer.php";
		require_once "Auth/OpenID/FileStore.php";
		// start session (needed for YADIS)
		session_start();
		// create file storage area for OpenID data
		$store = new Auth_OpenID_FileStore($conf['tmpdir'] . '/openid');
		// create OpenID consumer
		$this->consumer = new Auth_OpenID_Consumer($store);
		return $this->consumer;
	}

	/**
	 * Handles the openid action
	 */
	function handle_act_preprocess(&$event, $param)
	{
		global $ID, $conf, $auth;

		$user = $_SERVER['REMOTE_USER'];
		
		// Do not ask the user a password he didn't set
		if ($event->data == 'profile') {
			$conf['profileconfirm'] = 0;
			if (preg_match('!^https?://!', $user)) {
				$this->_redirect( $this->_self('openid') );
			}
		}

		if ($event->data != 'openid' && $event->data != 'logout') {
			// Warn the user to register an account if he's using a not registered OpenID
			// and if registration is possible
			if (preg_match('!^https?://!', $user)) {
				if ($auth && $auth->canDo('addUser') && actionOK('register')) {
					$message = sprintf($this->getLang('complete_registration_notice'), $this->_self('openid'));
					msg($message, 2);
				}
			}
		}

		if ($event->data == 'openid') {

			// not sure this if it's useful there
			$event->stopPropagation();
			$event->preventDefault();
			$conf_allowedproviders = $this->getConf('allowedproviders');

			if (isset($_POST['mode']) && ($_POST['mode'] == 'login' || $_POST['mode'] == 'add')) {

				// See if submitted provider is allowed or not
				if (empty($conf_allowedproviders)) {
					// Allow any provider
					// User needs to fill in full identifier URL.
					$openid_identifier = $_POST['openid_identifier'];
				} else {
					// Get it from the selected option
					$openid_provider = $_POST['openid_provider'];

					// Create identifier for user. Replace '*' by username.
					$openid_identifier = $openid_provider;
					$openid_identifier = str_replace('*', $_POST['nickname'], $openid_identifier);
					
					$validprovider   = $this->check_provider($openid_provider);
					$valididentifier = $this->check_identifier($openid_identifier);

					if( !$validprovider or !$valididentifier ) {
						msg($this->getLang('enter_valid_openid_error'), -1);
						return;
					}
				}

				// we try to login with the OpenID submited
				$consumer = $this->getConsumer();
				$auth = $consumer->begin($openid_identifier);
				if (!$auth) {
					msg($this->getLang('enter_valid_openid_error') . ':'.$openid_identifier, -1);
					return;
				}

				// add an attribute query extension if we've never seen this OpenID before.
				$associations = $this->get_associations();
				if (!isset($associations[$openid])) {
					require_once('Auth/OpenID/SReg.php');
					$e = Auth_OpenID_SRegRequest::build(array(),array('nickname','email','fullname'));
					$auth->addExtension($e);
				}

				// redirect to OpenID provider for authentication

				// this fix an issue with mod_rewrite with JainRain library
				// when a parameter seems to be non existing in the query
				$return_to = $this->_self('openid') . '&id=' . $ID;

				$url = $auth->redirectURL(DOKU_URL, $return_to);
				$this->_redirect($url);

			} else if (isset($_POST['mode']) && $_POST['mode'] == 'extra') {
				// we register the user on the wiki and associate the account with his OpenID
				$this->register_user();

			} else if (isset($_POST['mode']) && $_POST['mode'] == 'delete') {
				foreach ($_POST['delete'] as $identity => $state) {
					$this->remove_openid_association($user, $identity);
				}

			} else if ($_GET['openid_mode'] == 'id_res') {
				$consumer = $this->getConsumer();
				$response = $consumer->complete($this->_self('openid'));
				// set session variable depending on authentication result
				if ($response->status == Auth_OpenID_SUCCESS) {
					$openid_identifier = $_GET['openid_identity'];
					
					$isallowed = $this->check_identifier($openid_identifier);

					if (!$isallowed) {
						msg($this->getlang('enter_valid_openid_error'), -1);
						return;
					}

					$openid = isset($_GET['openid1_claimed_id']) ? $_GET['openid1_claimed_id'] : $_GET['openid_claimed_id'];
					if (empty($openid)) {
						msg("Can't find OpenID claimed ID.", -1);
						return false;
					}

					if (isset($user) && !preg_match('!^https?://!', $user)) {
						$result = $this->register_openid_association($user, $openid);
						if ($result) {
							msg($this->getLang('openid_identity_added'), 1);
						}
					} else {
						$authenticate = $this->login_user($openid);
						if ($authenticate) {
							// redirect to the page itself (without do=openid)
							$this->_redirect(wl($ID));
						}
					}

				} else {
					msg($this->getLang('openid_authentication_failed'), -1);
					return;
				}

			} else if ($_GET['openid_mode'] == 'cancel') {
				// User cancelled the authentication
				msg($this->getLang('openid_authentication_canceled'), 0);
				return; // fall through to what ever action was called
			}

		}
		
		return; // fall through to what ever action was called
	}

	/**
	 * Create the OpenID login/complete forms
	 */
	function handle_act_unknown(&$event, $param)
	{
		global $auth, $ID;

		if ($event->data != 'openid') {
			return;
		} 

		$event->stopPropagation();
		$event->preventDefault();

		$user = $_SERVER['REMOTE_USER'];

		if (empty($user)) {
			print $this->plugin_locale_xhtml('intro');
			print '<div class="centeralign">'.NL;
			$form = $this->get_openid_form('login');
			html_form('register', $form);
			print '</div>'.NL;
		} else if (preg_match('!^https?://!', $user)) {
			echo '<h1>', $this->getLang('openid_account_fieldset'), '</h1>', NL;
			if ($auth && $auth->canDo('addUser') && actionOK('register')) {
				echo '<p>', $this->getLang('openid_complete_text'), '</p>', NL;
				print '<div class="centeralign">'.NL;
				$form = $this->get_openid_form('extra');
				html_form('complete', $form);
				print '</div>'.NL;
			} else {
				echo '<p>', sprintf($this->getLang('openid_complete_disabled_text'), wl($ID)), '</p>', NL;
			}
		} else {
			echo '<h1>', $this->getLang('openid_identities_title'), '</h1>', NL;
			$identities = $this->get_associations($_SERVER['REMOTE_USER']);
			if (!empty($identities)) {
				echo '<form action="' . $this->_self('openid') . '" method="post"><div class="no">';
				echo '<table>';
				foreach ($identities as $identity => $user) {
					echo '<tr>';
					echo '<td width="10"><input type="checkbox" name="delete[' . htmlspecialchars($identity) . ']"/></td>';
					echo '<td>' . $identity . '</td>';
					echo '</tr>';
				}
				echo '</table>';
				echo '<input type="hidden" name="mode" value="delete"/>';
				echo '<input type="submit" value="' . $this->getLang('delete_selected_button') . '" class="button" />';
				echo '</div></form>';
			} else {
				echo '<p>' . $this->getLang('none') . '</p>';
			}
			echo '<h1>' . $this->getLang('add_openid_title') . '</h1>';
			print '<div class="centeralign">'.NL;
			$form = new Doku_Form('openid__login', script());
			$form->addHidden('do', 'openid');
			$form->addHidden('mode', 'add');
			$form->addElement(
				form_makeTextField(
					'openid_identifier', isset($_POST['openid_identifier']) ? $_POST['openid_identifier'] : '',
					$this->getLang('openid_url_label'), 'openid__url', 'block', array('size'=>'50')
				)
			);
			$form->addElement(form_makeButton('submit', '', $this->getLang('add_button')));
			html_form('add', $form);
			print '</div>'.NL;
		}
	}

	/**
	 * Generate the OpenID login/complete forms
	 */
	function get_openid_form($mode)
	{
		global $USERINFO, $lang, $conf;
		
		$c = 'block';
		$p = array('size'=>'50');


		$conf_allowedproviders = $this->getConf('allowedproviders');
		if( empty($conf_allowedproviders) ) {
			$providers = null;
		} else {
			$providers = array();
			foreach( explode(' ', $conf_allowedproviders) as $provider) {
				$provider_label = parse_url($provider, PHP_URL_HOST);
				$providers[$provider] = $provider_label;
			}
		}

		$form = new Doku_Form('openid__login', script());
		$form->addHidden('id', $_GET['id']);
		$form->addHidden('do', 'openid');
		if ($mode == 'extra') {
			$form->startFieldset($this->getLang('openid_account_fieldset'));
			$form->addHidden('mode', 'extra');
			$form->addElement(form_makeTextField('nickname', $_REQUEST['nickname'], $lang['user'], null, $c, $p));
			$form->addElement(form_makeTextField('email', $_REQUEST['email'], $lang['email'], '', $c, $p));
			$form->addElement(form_makeTextField('fullname', $_REQUEST['fullname'], $lang['fullname'], '', $c, $p));
			$form->addElement(form_makeButton('submit', '', $this->getLang('complete_button')));
		} else {
			$form->startFieldset($this->getLang('openid_login_fieldset'));
			$form->addHidden('mode', 'login');

			if ( !is_array($providers) ) {
				$form->addElement(form_makeTextField('openid_identifier', $_REQUEST['openid_identifier'], $this->getLang('openid_url_label'), 'openid__url', $c, $p));
			} else {
				$params = array();
				$form->addElement(
					form_makeListboxField(
						'openid_provider',
						$providers,
						$_REQUEST['openid_provider'], #default
						$this->getLang('openid_provider_label'),
						'',
						'block',
						$params
					)
				);
				$form->addElement(form_makeTextField('nickname', $_REQUEST['nickname'], $lang['user'], null, $c, $p));
			}
			$form->addElement(form_makeButton('submit', '', $lang['btn_login']));
		}
		$form->endFieldset();
		return $form;
	}
	
	/**
	 * Insert link to OpenID into usual login form
	 */
	function handle_login_form(&$event, $param)
	{
		if ($this->getConf('loginopenid') && empty($_GET['disableopenid'])) {
			$event->data = $this->get_openid_form('login');
			$pos = $event->data->findElementByAttribute('type', 'submit');
			$msg = $this->getLang('login_link_normal');
			$msg = sprintf("<p>$msg</p>", wl($ID, 'do=login&disableopenid=1'));
			$event->data->insertElement($pos+2, $msg);
		} else {
			$msg = $this->getLang('login_link');
			$msg = sprintf("<p>$msg</p>", $this->_self('openid'));
			$pos = $event->data->findElementByAttribute('type', 'submit');
			$event->data->insertElement($pos+2, $msg);
		}
	}
	
	function handle_profile_form(&$event, $param)
	{
		echo '<p>', sprintf($this->getLang('manage_link'), $this->_self('openid')), '</p>';
	}
	
	/**
	* Gets called when a OpenID login was succesful
	*
	* We store available userinfo in Session and Cookie
	*/
	function login_user($openid)
	{
		global $USERINFO, $auth, $conf;

		// look for associations passed from an auth backend in user infos
		$users = $auth->retrieveUsers();
		foreach ($users as $id => $user) {
			if (isset($user['openids'])) {
				foreach ($user['openids'] as $identity) {
					if ($identity == $openid) {
						return $this->update_session($id);
					}
				}
			}
		}

		$associations = $this->get_associations();

		// this openid is associated with a real wiki user account
		if (isset($associations[$openid])) {
			$user = $associations[$openid];
			return $this->update_session($user);
		}

		// no real wiki user account associated

		// note that the generated cookie is invalid and will be invalided
		// when the 'auth_security_timeout' expire
		$this->update_session($openid);

		$redirect_url = $this->_self('openid');

		$sregs = array('email', 'nickname', 'fullname');
		foreach ($sregs as $sreg) {
			if (!empty($_GET["openid_sreg_$sreg"])) {
				$redirect_url .= "&$sreg=" . urlencode($_GET["openid_sreg_$sreg"]);
			}
		}

		// we will advice the user to register a real user account
		$this->_redirect($redirect_url);
	}

	/**
	 * Register the user in DokuWiki user conf,
	 * write the OpenID association in the OpenID conf
	 */
	function register_user()
	{
		global $ID, $lang, $conf, $auth, $openid_associations;

		if(!$auth->canDo('addUser')) return false;

		$_POST['login'] = $_POST['nickname'];

		// clean username
		$_POST['login'] = preg_replace('/.*:/','',$_POST['login']);
		$_POST['login'] = cleanID($_POST['login']);
		// clean fullname and email
		$_POST['fullname'] = trim(preg_replace('/[\x00-\x1f:<>&%,;]+/','',$_POST['fullname']));
		$_POST['email']    = trim(preg_replace('/[\x00-\x1f:<>&%,;]+/','',$_POST['email']));

		if (empty($_POST['login']) || empty($_POST['fullname']) || empty($_POST['email'])) {
			msg($lang['regmissing'], -1);
			return false;
		} else if (!mail_isvalid($_POST['email'])) {
			msg($lang['regbadmail'], -1);
			return false;
		}

		// okay try to create the user
		if (!$auth->createUser($_POST['login'], auth_pwgen(), $_POST['fullname'], $_POST['email'])) {
			msg($lang['reguexists'], -1);
			return false;
		}

		$user = $_POST['login'];
		$openid = $_SERVER['REMOTE_USER'];

		// we update the OpenID associations array
		$this->register_openid_association($user, $openid);

		$this->update_session($user);

		// account created, everything OK
		$this->_redirect(wl($ID));
	}
		
	/**
	 * Update user sessions
	 *
	 * Note that this doesn't play well with DokuWiki 'auth_security_timeout' configuration.
	 *
	 * So, you better set it to an high value, like '60*60*24', the user being disconnected
	 * in that case one day after authentication
	 */
	function update_session($user)
	{
		session_start();

		global $USERINFO, $INFO, $conf, $auth;

		$_SERVER['REMOTE_USER'] = $user;

		$USERINFO = $auth->getUserData($user);
		if (empty($USERINFO)) {
			$USERINFO['pass'] = 'invalid';
			$USERINFO['name'] = 'OpenID';
			$USERINFO['grps'] = array($conf['defaultgroup'], 'openid');
		}

		$pass = PMA_blowfish_encrypt($USERINFO['pass'], auth_cookiesalt());
		auth_setCookie($user, $pass, false);

		// auth data has changed, reinit the $INFO array
		$INFO = pageinfo();

		return true;
	}

	function register_openid_association($user, $openid)
	{
		$associations = $this->get_associations();
		if (isset($associations[$openid])) {
			msg($this->getLang('openid_already_user_error'), -1);
			return false;
		}
		$associations[$openid] = $user;
		$this->write_openid_associations($associations);
		return true;
	}

	function remove_openid_association($user, $openid)
	{
		$associations = $this->get_associations();
		if (isset($associations[$openid]) && $associations[$openid] == $user) {
			unset($associations[$openid]);
			$this->write_openid_associations($associations);
			return true;
		}
		return false;
	}

	function write_openid_associations($associations)
	{
		$cfg = '<?php' . "\n";
		foreach ($associations as $id => $login) {
			$cfg .= '$openid_associations["' . addslashes($id) . '"] = "' . addslashes($login) . '"' . ";\n";
		}
		file_put_contents(DOKU_CONF.'openid.php', $cfg);
		$this->openid_associations = $associations;
	}

	function get_associations($username = null)
	{
		if (isset($this->openid_associations)) {
			$openid_associations = $this->openid_associations;
		} else if (file_exists(DOKU_CONF.'openid.php')) {
			// load OpenID associations array
			$openid_associations = array();
			include(DOKU_CONF.'openid.php');
			$this->openid_associations = $openid_associations;
		} else {
			$this->openid_associations = $openid_associations = array();
		}
		// Maybe is there a better way to filter the array
		if (!empty($username)) {
			$user_openid_associations = array();
			foreach ((array)$openid_associations as $openid => $login) {
				if ($username == $login) {
					$user_openid_associations[$openid] = $login;
				}
			}
			return $user_openid_associations;
		}
		return $openid_associations;
	}
	
	function allowedproviders()
	{
		$conf_allowedproviders = $this->getConf('allowedproviders');
		if (empty($conf_allowedproviders) ) {
			return array();
		} else {
			return explode(' ', $conf_allowedproviders);
		}
	}

	function user_getproviders($user)
	{
		if (empty($user)) {
			return array();
		}
		// See if logged in through openid
		if ( $this->check_identifier($user) ) {
			return array(parse_url($user, PHP_URL_HOST));
		}
		$associations = $this->get_associations($user);
		$providers=array();
		foreach ($associations as $openid_identifier => $username) {
			$providers[] = parse_url($openid_identifier, PHP_URL_HOST);
		}
		return $providers;
	}

	/**
	 * Inspired by: http://subversion.fem.tu-ilmenau.de/websvn/wsvn/dokuwiki/ipgroup/action.php
	 */ 
	function assigngroup(&$event, $param)
	{
		global $USERINFO, $INFO, $ID;
		$user = $_SERVER['REMOTE_USER'];
		$providers = $this->user_getproviders($user);
		foreach ($providers as $provider) {
			if (!empty($USERINFO)) {
				$USERINFO['grps'][] = $provider;
			}
			$INFO['userinfo']['grps'][] = $provider;
			$INFO['perm']     = auth_aclcheck($ID, '', $INFO['userinfo']['grps']);
			$INFO['writable'] = false;
			if ($INFO['perm'] >= AUTH_EDIT) {
				if (file_exists($INFO['filepath'])) {
					$INFO['writable'] = is_writable($INFO['filepath']);
				} else {
					$INFO['writable'] = is_writable(dirname($INFO['filepath']));
				}
			}
		}
	}

	function check_provider($openid_provider)
	{
			$conf_allowedproviders = $this->getConf('allowedproviders');
			if (empty($conf_allowedproviders) ) {
				return true;
			}
			$allowedproviders = explode(' ', $conf_allowedproviders);
			$host = parse_url($openid_provider, PHP_URL_HOST);
			foreach ($allowedproviders as $provider) {
				if (parse_url($provider, PHP_URL_HOST) == $host) {
					return true;
				}
			}
			return false;
	}
	
	function check_identifier($openid_identifier)
	{
			return $this->check_provider($openid_identifier);
	}
}
