<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules;

class Firewall extends \FreePBX_Helpers implements \BMO {

	public function __construct($freepbx = null) {
		if ($freepbx == null)
			throw new \Exception("Not given a FreePBX Object");

		$this->FreePBX = $freepbx;
		$this->db = $freepbx->Database;
		$this->astman 	= $this->FreePBX->astman;
		$this->astspooldir  = $this->FreePBX->Config->get("ASTSPOOLDIR"); 
		$this->astetcdir  = $this->FreePBX->Config->get("ASTETCDIR"); 
		$this->astlogdir  = $this->FreePBX->Config->get("ASTLOGDIR"); 
		$this->webuser = $this->FreePBX->Config->get('AMPASTERISKWEBUSER');
	    $this->webgroup = $this->FreePBX->Config->get("AMPASTERISKWEBGROUP");
	}
	
	public function getTrustedZone($from){
		$networkmaps = $this->FreePBX->Firewall->get_networkmaps();
		$trusted = "";
		foreach($networkmaps as $ip => $type){
			if($type == $from){
				$trusted .= (string) "$ip\n";
			}
		}
		return $trusted;
	}

	public function intrusion_detection_status() { 
		exec('pidof -x fail2ban-server', $out, $ret);
		if ($ret == 0) {
			return "running";
		} else {
			return "stopped";
		} 
	} 

	public function getExtRegistered(){
		/**
		 * Get all IP addresses of registered extensions.
		 * Whatever technololgies, SIP, PJSIP, IAX2
		 */
		$ip_reg			= array();
		$sip_driver 	= $this->astman->Command("sip show peers");
		$pjsip_driver 	= $this->astman->Command("pjsip show endpoints");
		$iax_driver 	= $this->astman->Command("iax2 show peers");
		$sip_driver		= (is_array($sip_driver)) && !empty($sip_driver["data"]) 		? explode("\n",$sip_driver["data"]) 	: array();
		$pjsip_driver	= (is_array($pjsip_driver)) && !empty($pjsip_driver["data"]) 	? explode("\n",$pjsip_driver["data"]) 	: array();
		$iax_driver		= (is_array($iax_driver)) && !empty($iax_driver["data"]) 		? explode("\n",$iax_driver["data"]) 	: array();

		foreach($sip_driver as $line => $content){
			if (preg_match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $content, $ip_match) && strpos($content,"OK") !== false) {
				$ip_reg[] = $ip_match[0];
			 }
		}

		foreach($pjsip_driver as $line => $content){
			if (preg_match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $content, $ip_match) && strpos($content,"Avail") !== false) {
				$ip_reg[] = $ip_match[0];
			 }
		}

		foreach($iax_driver as $line => $content){
			if (preg_match('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $content, $ip_match) && strpos($content,"OK") !== false) {
				$ip_reg[] = $ip_match[0];
			 }
		}

		return implode("\n", array_unique($ip_reg));
	}

	public function get_astspooldir() {
		return $this->astspooldir; 
	}

	public function get_astetcdir() {
		return $this->astetcdir; 
	}

	public function get_astlogdir() {
		return $this->astlogdir; 
	}

	public static $dbDefaults 		= array("status" => false);
	public static $filesCustomRules = array('ipv4' => '/etc/firewall-4.rules', 'ipv6' => '/etc/firewall-6.rules');
	public static $filesLog 		= Null;	
	
	public static function logfile_init() {
		$astlogdir  = \FreePBX::Config()->get("ASTLOGDIR");
		self::$filesLog = array('err' => $astlogdir.'/firewall.err', 'out' => $astlogdir.'/firewall.log');
	}
	
	private static $services = false;

	public function install() {
		// Upgrade at 13.0.47 - If the firewall is enabled, create the filesystem
		// flag to say that it is.
		if ($this->getConfig("status")) {
			$file = "/etc/asterisk/firewall.enabled";
			if (!file_exists($file)) {
				touch($file);
				chown($file, $this->webuser);
				chgrp($file, $this->webgroup);
			}
		}
		// 13.0.54 - Add cronjob to restart it if it crashes
		$this->addCronJob();
		$this->addsyncjob();
		$nt = \FreePBX::Notifications();
		$nt->add_warning("firewall", "1", _("Intrusion detection handling method"), _("Intrusion detection handling method is been updated recently. Please clear your browser cache and try if you are having issue with Intrusion Detection Start/Restart/Stop button.") , "", $reset=true, $candelete=true);
	}
	
	public function uninstall() {
		// Disable the firewall when it's uninstalled,
		// so if it is automatically reinstalled at some
		// point, it doesn't start.
		$this->setConfig("status", false);
		@unlink("/etc/asterisk/firewall.enabled");
		$o = \FreePBX::OOBE()->getConfig("completed");
		if (is_array($o)) {
			unset ($o['firewall']);
			\FreePBX::OOBE()->setConfig("completed", $o);
			$this->setConfig("oobeanswered", array());
		}
		$this->removeCronJob();
		$this->removesyncjob();
		$this->setConfig("first_install", "yes");
	}

	public function backup() {}
	public function restore($backup) {}

	public function get_networkmaps(){
		return $this->getConfig("networkmaps");
	}

	public function chownFreepbx() {
		$files = array(
			array('type' => 'execdir',
			'path' => __DIR__."/hooks",
			'perms' => 0755),
			array('type' => 'execdir',
			'path' => __DIR__."/bin",
			'perms' => 0755),
			array('type' => 'execdir',
			'path' => __DIR__."/phar",
			'perms' => 0755)
		);
		return $files;
	}

	public function oobeHook() {
		include __DIR__.'/OOBE.class.php';
		$o = new Firewall\OOBE($this);
		return $o->oobeRequest();
	}

	public function dashboardService() {
		// Check to see if Firewall is enabled. Warn if it's not.
		$status = array(
			'title' => _("System Firewall"),
			'order' => 3,
		);

		if ($this->getConfig("status")) {
			$status = array_merge($status, $this->Dashboard()->genStatusIcon('ok', _("Firewall Active")));
		} else {
			$status = array_merge($status, $this->Dashboard()->genStatusIcon('error', _("Firewall Disabled")));
			return array($status);
		}

		if ($this->isNotReady()) {
			$status = array_merge($status, $this->Dashboard()->genStatusIcon('warning', _("Starting up")));
			return array($status);
		}

		// We're meant to be running, check that the firewall service is.
		exec("pgrep -f hooks/voipfirewalld", $out, $ret);
		// Clobber the $status if it's not running
		if ($ret != 0) {
			$status = array_merge($status, $this->Dashboard()->genStatusIcon('error', _("Firewall Service not running!")));
			$status['order'] = 1;
		}

		// If there are any interfaces that are in 'Trusted', yell loudly about that, too
		$trusted = array(
			'title' => _("Firewall Configuration"),
			'order' => 3
		);

		$foundtrustedint = false;
		$foundnewint = false;
		$error = false;
		$ints = $this->getInterfaces();
		foreach ($ints as $i => $conf) {
			// Is it an alias? If so, ignore it, we can't set it anyway
			if ($conf['config']['PARENT']) {
				continue;
			}

			// Does this not have a zone?
			if (!isset($conf['config']['ZONE'])) {
				// If it's got IP addresses, it's new. Otherwise, we can just ignore it.
				if ($conf['addresses']) {
					$foundnewint = $i;
				}
				break;
			}

			$runningzone = $this->getZone($i);
			if ($conf['config']['ZONE'] !== $runningzone) {
				$error = $i;
				break;
			} elseif ($runningzone === "trusted") {
				$foundtrustedint = $i;
				break;
			}
		}

		if ($error) {
			$trusted = array_merge($trusted, $this->Dashboard()->genStatusIcon('error', _("Firewall Integrity Failed")));
			$this->Notifications()->add_critical('firewall', 'zoneerror', _("Firewall Integrity Failed"),
				sprintf(_("Interface %s is not in the correct zone. This can be caused by manual alterations of iptables, or, an unexpected error. Please restart the firewall service."), $error),
				"?display=firewall",
				true, // Reset on update.
				true); // Can delete
			return array($status, $trusted);
		}
		// No errors found. Remove zone errors, if there are any
		$this->Notifications()->delete('firewall', 'zoneerror');
			
		if ($foundnewint) { // Have we found a new interface?
			$trusted = array_merge($trusted, $this->Dashboard()->genStatusIcon('error', _("New Interface Detected")));
			$trusted['order'] = 1;
			$this->Notifications()->add_critical('firewall', 'newint', _("New Interface Detected"),
				sprintf(_("A new, unconfigured, network interface has been detected. Please assign interface '%s' to a zone."), $foundnewint),
				"?display=firewall&page=about&tab=interfaces",
				true, // Reset on update.
				false); // Can delete
			return array($status, $trusted);
		} elseif ($foundtrustedint) { // If we've found a trusted interface, this is bad, yell.
			$trusted = array_merge($trusted, $this->Dashboard()->genStatusIcon('error', _("Trusted Interface Detected")));
			$trusted['order'] = 1;
			// Add core notification
			$this->Notifications()->add_critical('firewall', 'trustedint', _("Trusted Interface Detected"),
				sprintf(_("A network interface that is assigned to the 'Trusted' zone has been detected. This is a misconfiguration. To ensure your system is protected from attacks, please change the default zone of interface '%s'."), $foundtrustedint),
				"?display=firewall&page=about&tab=interfaces",
				true, // Reset on update.
				false); // Can delete
			return array($status, $trusted);
		} else {
			// No errors with interfaces, so delete any old notifications
			$this->Notifications()->delete('firewall', 'newint');
			$this->Notifications()->delete('firewall', 'trustedint');
		}

		// Now we need to validate that we DO have a trusted network or host. 
		// If we dont', this should be a warning, not an error.
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}

		$foundtrustednet = false;
		foreach ($nets as $name => $zone) {
			if ($zone === "trusted") {
				$foundtrustednet = true;
				break;
			}
		}

		if ($foundtrustednet) {
			// Yup, there's at least one!
			$trusted = array_merge($trusted, $this->Dashboard()->genStatusIcon('ok', _("Trusted Management Network defined")));
		} else {
			$trusted = array_merge($trusted, $this->Dashboard()->genStatusIcon('warning', _("No Trusted Management Network")));
			// Add core notification
			$this->Notifications()->add_warning('firewall', 'trustednet', _("No Trusted Network or Host defined"),
				_("No Trusted Network or Host has been defined. Every server should have a 'Trusted' host or network to ensure that in case of configuration error, the machine is still accessible."),
				"?display=firewall&page=about&tab=networks",
				true, // Reset on update.
				true); // Can delete
		}

		return array($status, $trusted);
	}

	// Run a sysadmin-managed root hook.
	public function runHook($hookname,$params = false) {
		// Runs a new style Syadmin hook
		if (!file_exists("/etc/incron.d/sysadmin")) {
			throw new \Exception("Sysadmin RPM not up to date, or not a known OS. Can not start System Firewall. See http://bit.ly/fpbxfirewall");
		}

		$basedir = $this->get_astspooldir()."/incron";
		if (!is_dir($basedir)) {
			throw new \Exception("$basedir is not a directory");
		}

		// Does our hook actually exist?
		if (!file_exists(__DIR__."/hooks/$hookname")) {
			throw new \Exception("Hook $hookname doesn't exist");
		}

		// So this is the hook I want to run
		$filename = "$basedir/firewall.$hookname";

		// If we have a modern sysadmin_rpm, we can put the params
		// INSIDE the hook file, rather than as part of the filename
		if (file_exists("/etc/sysadmin_contents_max")) {
			$fh = fopen("/etc/sysadmin_contents_max", "r");
			if ($fh) {
				$max = (int) fgets($fh);
				fclose($fh);
			}
		} else {
			$max = false;
		}

		if ($max > 65535 || $max < 128) {
			$max = false;
		}

		// Do I have any params?
		$contents = "";
		if ($params) {
			// Oh. I do. If it's an array, json encode and base64
			if (is_array($params)) {
				$b = base64_encode(gzcompress(json_encode($params)));
				// Note we derp the base64, changing / to _, because this may be used as a filepath.
				if ($max) {
					if (strlen($b) > $max) {
						throw new \Exception("Contents too big for current sysadmin-rpm. This is possibly a bug!");
					}
					$contents = $b;
					$filename .= ".CONTENTS";
				} else {
					$filename .= ".".str_replace('/', '_', $b);
					if (strlen($filename) > 200) {
						throw new \Exception("Too much data, and old sysadmin rpm. Please run 'yum update'");
					}
				}
			} elseif (is_object($params)) {
				throw new \Exception("Can't pass objects to hooks");
			} else {
				// Cast it to a string if it's anything else, and then make sure
				// it doesn't have any spaces.
				$filename .= ".".preg_replace("/[[:blank:]]+/", "", (string) $params);
			}
		}
		
		$fh = fopen($filename, "w+");
		if ($fh === false) {
			// WTF, unable to create file?
			throw new \Exception("Unable to create hook trigger '$filename'");
		}

		// Put our contents there, if there are any.
		fwrite($fh, $contents);

		// As soon as we close it, incron does its thing.
		fclose($fh);

		// Wait for up to 5 seconds and make sure it's been deleted.
		$maxloops = 10;
		$deleted = false;
		while ($maxloops--) {
			if (!file_exists($filename)) {
				$deleted = true;
				break;
			}
			usleep(500000);
		}

		if (!$deleted) {
			throw new \Exception("Hook file '$filename' was not picked up by Incron after 5 seconds. Is it not running?");
		}
		return true;
	}

	public function startFirewall() {
		$this->runHook("firewall");
	}

	public function stopFirewall() {
		$this->runHook("stopfirewall");
	}

	public function fixCustomRules($tiemout = 0) {
		$this->runHook("fixcustomrules");
		if ($tiemout > 0) {
			$completed = false;
			while ( $i <= $timeout ) {
				$completed = $this->check_custom_rules_files();
				if ( $completed ) { break; }
				$i++;
				sleep(1);
			}
			return $completed;
		}
	}

	public function enableLeRules() {
		// use sysadmin LetsEncrypt service port if defined
		// else, we don't know which http service, so open all http
		
		$as = $this->getAdvancedSettings();
		if ($as['lefilter'] == "disabled") {
			return true;
		}

		$leports = array();
		$leservice = $this->getService('letsencrypt');

		if (isset($leservice['fw'][0]['port'])) {
        		$leports[] = $leservice['fw'][0]['port'];
		} else { 
			$allservices = $this->getServices();
			unset($allservices['custom']); // ignore custom services
			foreach ($allservices as $services) {
				foreach($services as $service) {
					$s = $this->getService($service);
					if (!$s['disabled']) { 
						foreach ($s['fw'] as $fw) { 
							if ($fw['leport']) {
								$leports[] = $fw['port'];
							}
						}
					}
				}
			}
		}

		return $this->runHook("updateipset", array('ipset' => 'lefilter', 'action' => 'add', 'ports' => $leports));
	}

	public function disableLeRules() {
		$as = $this->getAdvancedSettings();
		if ($as['lefilter'] == "disabled") {
			return true;
		}
		return $this->runHook("updateipset", array('ipset' => 'lefilter', 'action' => 'flush'));
	}

	public function uninstallHook() {
		$this->runHook("uninstall");
	}

	public function isEnabled() {
		return $this->getConfig("status");
	}

	// If the machine is currently in safe mode, return true.
	public function isNotReady() {
		return file_exists("/var/run/firewalld.safemode");
	}

	public function showLockoutWarning() {
		if (!$this->isTrusted()) {
			$thishost = $this->detectHost();
			print "<div class='alert alert-warning' id='lockoutwarning'>";
			print "<p>".sprintf(_("The client machine you are using to manage this server (<tt>%s</tt>) is <strong>not</strong> a member of the Trusted zone. It is highly recommended to add this client to your Trusted Zone to avoid accidental lockouts."), $thishost)."</p>";
			print "<p><a href='?display=firewall&page=advanced&tab=shortcuts'>"._("You can add the host automatically here.")."</a></p>";
			print "</div>";
		}
	}

	public function showDisabled() {
		// Firewall functions disabled
		return load_view(__DIR__."/views/disabled.php", array("fw" => $this));
	}

	public function getRightNav($page) {
		return load_view(__DIR__."/views/bootnav.php", array("fw" => $this, "thispage" => $page));
	}

	public function sysadmin_info(){
		$module = \module_functions::create();
		$result = $module->getinfo('sysadmin', MODULE_STATUS_ENABLED);
		return (empty($result["sysadmin"])) ? '' : $result;
	}
	
	/**
	 * showIDPage for Sysadmin menu
	 * This page is displayed only if Firewall is disabled.
	 *
	 * 
	 * @return string
	 */
	public function showIDPage(){	
		return __DIR__."/views/intrusion_detection.php";
	}
	
	/**
	 * getIDDataPage  : Prepare everything for I.D page
	 * This page is shared with Firewall and Sysadmin module.
	 * The common data are there.
	 *
	 * @return array
	 */
	public function getIDDataPage(){
		$asfw   				= $this->getAdvancedSettings();
		$indetec                = $this->FreePBX->Sysadmin->getIntrusionDetection();
		$indetec["idregextip"]  = $this->getConfig("idregextip")  == "true"   ? "Active"  : "";
		$indetec["trusted"]     = $this->getConfig("trusted")     == "true"   ? "Active"  : "";
		$indetec["local"]       = $this->getConfig("local")       == "true"   ? "Active"  : "";
		$indetec["other"]       = $this->getConfig("other")       == "true"   ? "Active"  : "";
		$indetec["idstatus"]    = $indetec["status"]              == "stopped"? "style='display: none;'": "";
		$indetec["legacy"]      = $asfw["id_sync_fw"]             == "legacy" ? "style='display: none;'": "";
		if($indetec["legacy"] == ""){
		  $indetec["ids"]["fail2ban_whitelist"] = preg_replace('!\n+!', chr(10), $this->getConfig("dynamic_whitelist"));
		}
		  
		$wl_filter              = "^(\b(?:\d{1,3}\.){3}\d{1,3}\b)$";                    // IPV4
		$wl_filter             .= "|^(\b(?:\d{1,3}\.){3}\d{1,3}\b)\/\d{1,2}$";          // IPV4 + subnet
		$wl_filter             .= "|^((\w|\d|[-\.]){1,})+(\w|\d|[-])$";                 // Domains
		$wl_filter             .= "|^()$";                                              // Nothing (CR)
		$wl_filter             .= "|^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}";        // IPV6 
		$wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,7}:";
		$wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}";
		$wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}";
		$wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}";
		$wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}";
		$wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}";
		$wl_filter             .= "|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})";
		$wl_filter             .= "|:((:[0-9a-fA-F]{1,4}){1,7}|:)";
		$wl_filter             .= "|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}";
		$wl_filter             .= "|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]";
		$wl_filter             .= "|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]";
		$wl_filter             .= "|(2[0-4]";
		$wl_filter             .= "|1{0,1}[0-9]){0,1}[0-9])";
		$wl_filter             .= "|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]";
		$wl_filter             .= "|(2[0-4]";
		$wl_filter             .= "|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]";
		$wl_filter             .= "|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$";
		
		$indetec["wl_filter"]   = $wl_filter;
		$indetec["id_sync_fw_legacy"]	= $asfw["id_sync_fw"] == "legacy" ? "checked" : "";
		$indetec["id_sync_fw_enabled"]  = $asfw["id_sync_fw"] != "legacy" ? "checked" : "";
		$indetec["id_service_enabled"]  = $asfw["id_service"] == "enabled" ? "checked" : "";
		$indetec["id_service_disabled"] = $asfw["id_service"] != "enabled" ? "checked" : "";

		return $indetec;
	}
	public function showPage($page) {
		if (strpos($page, ".") !== false) {
			throw new \Exception("Invalid page name $page");
		}

		// Check to see if it's 'zones', which means it's an old notification.
		if ($page == "zones") {
			$page = "about";
			$_REQUEST['tab'] = "interfaces";
		}

		$view = __DIR__."/views/page.$page.php";
		if (!file_exists($view)) {
			throw new \Exception("Can't find page $page");
		}		

		return load_view($view, array("fw" => $this, "module_status" => $this->sysadmin_info()));
	}

	public function getipzone($from){
		switch($from){
			case "custom_whitelist":
				$result = $this->getConfig("custom_whitelist");
				break;
			case "extregips":
				$result = $this->getExtRegistered();
				break;
			case "trusted":
				$result = $this->getTrustedZone("trusted");
				break;
			case "local":
				$result = $this->getTrustedZone("internal");
				break;
			case "other":
				$result = $this->getTrustedZone("other");
				break;
			case "all": 
				$list = array();
				if($this->getConfig("idregextip") == "true" ){
					$list["Ext. Registered"] = explode("\n", $this->getipzone("extregips"));
				}
				if($this->getConfig("trusted") == "true"){
					$list["Trusted"] = explode("\n", $this->getipzone("trusted"));
				}
				if($this->getConfig("local") == "true"){
					$list["Local"] = explode("\n", $this->getipzone("local"));
				}
				if($this->getConfig("other")== "true"){
					$list["Other"] = explode("\n", $this->getipzone("other"));
				}
				$list["Custom"] = explode("\n",$this->getConfig("custom_whitelist"));
				return $list;
			default:
				$result = "";				
		}
		return preg_replace('!\n+!', chr(10), $result);
	}

	public function buildCustomWhitelist($wl){
		/**
		 * Remove duplicated entries
		 */
		$currentwl	= $this->getConfig("custom_whitelist");
		$both 		= $currentwl."\n".$wl;
		$both 		= preg_replace('!\n+!', chr(10), $both);
		$both 		= explode("\n", $both);
		$result 	= implode("\n", array_unique($both));
		$this->setConfig("custom_whitelist",$result);
		return $result;
	}

	public function updateWhitelist($wl = ""){
		$sa = $this->sysadmin_info();
		if(empty($sa)){
			return false;
		}
		if(!$this->FreePBX->Sysadmin->isActivated()){
			return false;
		}

		/**
		 * Used by console to syncing / updating the whitelist dynamically.
		 * Only the difference is used between before and after the synchronisation.
		 */
		if(is_array($wl)){
			/**
			 * Generate a string whitelist when getipzone("all") is used to get all ips
			 * with the arg : all, it returns an array with all zones including their ips.
			 */ 
			foreach($wl as $zone => $ips){
				foreach($ips as $value){
					$list[] = $value;
				}
			}
			
			$wl = implode("\n",$list);
		}
		$this->runHook("get-dynamic-ignoreip");
		$wl 			 = preg_replace('!\n+!', chr(10), $wl);
		$previous_ignore = preg_replace('!\n+!', chr(10), $this->getConfig("dynamic_whitelist"));
		$previous_ignore = explode("\n",$previous_ignore);
		$current_ignore  = explode("\n", $wl);
		
		// rebuild arrays 
		foreach($previous_ignore as $key => $line){
			if(empty($line) || $line == "" ){
				unset($previous_ignore[$key]);
			}
		}

		foreach($current_ignore as $key => $line){
			if(empty($line) || $line == "" ){
				unset($current_ignore[$key]);
			}
		}

		// Get inet
		$ifconfig = fpbx_which("ifconfig");
		exec($ifconfig." -a | grep 'inet' | grep -v 'inet6' | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'", $inet, $ret);

		// Removing IP from the dynamic whitelist.
		$todel_ignore = array_diff($previous_ignore, $current_ignore);
		foreach($todel_ignore as $line){
			if(!in_array($line, $inet)){
				$this->runHook("dynamic-jails", array("action" => "delignoreip", "ip" => $line ));
			} 
		}

		// Add IP from the dynamic whitelist.
		$toadd_ignore = array_diff($current_ignore, $previous_ignore);
		foreach($toadd_ignore as $line){				
			if(!in_array($line, $inet)){
				$this->runHook("dynamic-jails", array("action" => "addignoreip", "ip" => $line ));
			} 
		}

		// Need to refresh and save the whitelist.
		$this->runHook("get-dynamic-ignoreip");
	}

	// Ajax calls
	public function ajaxRequest($req, &$settings) {
		return true;
	}

	public function ajaxHandler() {
		$asfw 		= $this->getAdvancedSettings();
		$IDsetting	= $this->FreePBX->Sysadmin->getIntrusionDetection();
		switch ($_REQUEST['command']) {
		case "switchlegacy":
			if(!empty($_REQUEST["option"])){
				switch($_REQUEST["option"]){
					case "enabled":
						if($asfw["id_sync_fw"] == "legacy"){
							// That was legacy to become enabled
							if($this->getConfig("idregextip") != "true" && $this->getConfig("trusted") != "true" && $this->getConfig("local") != "true" && $this->getConfig("other") != "true"){
								// For the first install only
								$this->setConfig("custom_whitelist", $IDsetting["ids"]["fail2ban_whitelist"]);
								$this->updateWhitelist($IDsetting["ids"]["fail2ban_whitelist"]);								
							}
						}						
					break;
					case "legacy":
						if($asfw["id_sync_fw"] != "legacy"){
							 // That was enabled to become legacy
							$IDsetting["ids"]["fail2ban_whitelist"] = preg_replace('!\n+!', chr(10), $this->getConfig("dynamic_whitelist"));
							$this->FreePBX->Sysadmin->sync_fw($IDsetting["ids"]);
						}	
					break;
				}
			}
			return true;
		case "move_to_whitelist":
			$custome_wl = $this->getConfig("custom_whitelist");
			$this->setConfig("custom_whitelist", preg_replace('!\n+!', chr(10),$custome_wl."\n".$_REQUEST["ip"]."\n"));
			$this->runHook("dynamic-jails", array("action" => "unbanip", "ip" => $_REQUEST["ip"] )); 
			return true;
		case "del_entire_whitelist":
			$this->setConfig("custom_whitelist", "");
			return true;
		case "del_custom" :
			$custom_wl = preg_replace('!\n+!', chr(10), str_replace($_REQUEST["ip"],"",$this->getConfig("custom_whitelist")));
			$this->setConfig("custom_whitelist", $custom_wl);
			return true; 
		case "getNewWhitelist":
			$result = array();
			if($_REQUEST["idregextip"] == "true" ){
				$list["Ext. Registered"] = explode("\n", $this->getipzone("extregips"));
			}
			if($_REQUEST["trusted"] == "true"){
				$list["Trusted"] = explode("\n", $this->getipzone("trusted"));
			}
			if($_REQUEST["local"] == "true"){
				$list["Local"] = explode("\n", $this->getipzone("local"));
			}
			if($_REQUEST["other"] == "true"){
				$list["Other"] = explode("\n", $this->getipzone("other"));
			}

			$list["Custom"] = explode("\n",$this->getConfig("custom_whitelist"));
			foreach($list as $key => $value){
				foreach($value as $ip){
					if(!empty($ip)){
						$result[] = array("action" => "", "source" => $ip, "type" => $key);
					}					
				}				
			}
			return $result;
		case "getwhitelist":
			$result = array();
			$list 	= $this->getipzone("all");
			foreach($list as $key => $value){
				foreach($value as $ip){
					if(!empty($ip)){
						$result[] = array("action" => "", "source" => $ip, "type" => $key);
					}					
				}				
			}
			return $result;
		case "getbannedlist":
			$result = array();
			if(count($IDsetting["banned"]) >= 1){
				foreach($IDsetting["banned"] as $line){
					$_ip = explode(" ",$line);
					preg_match_all('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/m', $_ip[0], $matches, PREG_SET_ORDER, 0);
					$result[] = array("action" => "", "ip" => trim($matches[0][0]), "type" => !empty($_ip[1]) ? $_ip[1] : _('Unknown') );
				}				
			}
			return $result;
		case "unban":
			return $this->runHook("dynamic-jails", array("action" => "unbanip", "ip" => $_REQUEST["ip"] )); 
		case "unbanall":
			if(count($IDsetting["banned"]) >= 1){
				foreach($IDsetting["banned"] as $line){
					preg_match_all('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/m', $line, $matches, PREG_SET_ORDER, 0);
					$this->runHook("dynamic-jails", array("action" => "unbanip", "ip" => trim($matches[0][0])));
				}
			}
			return true;
		case "saveids":
			$current_ids = $IDsetting["ids"];
			unset($current_ids["fail2ban_whitelist"]);

			$this->setConfig("idregextip", $_REQUEST['idregextip']);
			$this->setConfig("trusted", $_REQUEST['trusted']);
			$this->setConfig("local", $_REQUEST['local']);
			$this->setConfig("other", $_REQUEST['other']);
            $ids["fail2ban_ban_time"] 	= $_REQUEST["ban_time"];
            $ids["fail2ban_max_retry"] 	= $_REQUEST["max_retry"];
            $ids["fail2ban_find_time"] 	= $_REQUEST["find_time"];
			$ids["fail2ban_email"] 		= $_REQUEST["email"];
			$diff = array_diff($current_ids, $ids);
			if($asfw["id_sync_fw"] != "legacy"){
				/**
				 * Enabled and Disabled mode
				 */
				$ids["fail2ban_whitelist"] = "";
				if(!empty($diff)){
					/**
					 * We update and restart Fail2ban if there is a difference on the common settings
					 * As these settings are not updated often. we are allowed to restart fail2ban.
					 */
					$this->FreePBX->Sysadmin->sync_fw($ids);
				}
				
				if(!empty($_REQUEST["whitelist"])){
					$this->setConfig("custom_whitelist", $this->buildCustomWhitelist($_REQUEST["whitelist"]) );
				}

				$list = $this->getipzone("all");
				foreach($list as $zone => $ips){
					foreach($ips as $value){
						$wl[] = $value;
					}
				}
				
				$wl = implode("\n",$wl);
				$this->updateWhitelist($wl);				
			}
			else{
				/**
				 * Legacy mode
				 */
				$ids["fail2ban_whitelist"] 	= empty($_REQUEST["whitelist"]) ? "" : $_REQUEST["whitelist"];
				$this->FreePBX->Sysadmin->sync_fw($ids);
			}			
			return true;
		case "stop_id":
			$this->FreePBX->Sysadmin->runHook("fail2ban-stop");
			while($this->intrusion_detection_status() == "running"){
				sleep(1);
			}

			return "stopped";
		case "start_id":
			$this->FreePBX->Sysadmin->runHook("fail2ban-generate");
			$this->FreePBX->Sysadmin->runHook("fail2ban-start");
			return true;
		case "getIPsZone":
			return $this->getipzone($_REQUEST["from"]);
		case "deletenetworks":
			// We are handed a JSON string
			if (!isset($_REQUEST['json'])) {
				throw new \Exception("No json?");
			}
			$nets = @json_decode($_REQUEST['json'], true);
			if (!is_array($nets)) {
				throw new \Exception("Invalid JSON");
			}
			$all_net = array();

			if($asfw["id_sync_fw"] == "enabled"){
				$ids 		= $IDsetting["ids"];
				foreach ($nets as $net) {
					$this->removeNetwork($net);
					$ids["fail2ban_whitelist"] = str_replace($net,"",$ids["fail2ban_whitelist"]);
				}
				$ids["fail2ban_whitelist"] = preg_replace('!\n+!', chr(10), $ids["fail2ban_whitelist"]); // remove double new lines
				$this->FreePBX->Sysadmin->sync_fw($ids);
			}
			else{
				foreach ($nets as $net) {
					$this->removeNetwork($net);
				}
			}
			return true;
		case "addnetworktozone":
			if (!isset($_REQUEST['net'])) {
				throw new \Exception("No net");
			}
			if (!isset($_REQUEST['zone'])) {
				throw new \Exception("No Zone");
			}
			$zones = $this->getZones();
			if (!isset($zones[$_REQUEST['zone']])) {
				throw new \Exception("Invalid zone $zone");
			}
			if (!isset($_REQUEST['description'])) {
				$descr = "";
			} else {
				$descr = trim($_REQUEST['description']);
			}
			$network2zone 	= $this->addNetworkToZone(trim($_REQUEST['net']), $_REQUEST['zone'], $descr);
			$net 			= $_REQUEST['net'];
			$global_net 	= "";
			if($asfw["id_sync_fw"] == "enabled"){
				switch($_REQUEST['zone']){
					case "trusted":
						$global_net = ($this->getConfig("trusted") == "true")? $net."\n" : "";
					break;
					case "internal":
						$global_net = ($this->getConfig("local") == "true")? $net."\n" : "";
					break;
					case "other":
						$global_net = ($this->getConfig("other") == "true")? $net."\n" : "";
					break;
				}
				$ids = $IDsetting["ids"];
				$ids["fail2ban_whitelist"] = preg_replace('!\n+!', chr(10), $ids["fail2ban_whitelist"]."\n".$global_net);
			}

			if($asfw["id_sync_fw"] == "enabled"){
				$this->FreePBX->Sysadmin->sync_fw($ids);
			}
			return $network2zone;
		case "updatenetworks":
			// We are handed a JSON string
			if (!isset($_REQUEST['json'])) {
				throw new \Exception("No json?");
			}
			$nets = @json_decode($_REQUEST['json'], true);
			if (!is_array($nets)) {
				throw new \Exception("Invalid JSON");
			}
			foreach ($nets as $net => $tmparr) {
				$global_net = "";
				$this->changeNetworksZone($net, $tmparr['zone'], $tmparr['description']);
				if($asfw["id_sync_fw"] == "enabled"){
					switch($tmparr['zone']){
						case "trusted":
							$global_net .= ($this->getConfig("trusted") == "true")? $net."\n" : "";
						break;
						case "internal":
							$global_net .= ($this->getConfig("local") == "true")? $net."\n" : "";
						break;
						case "other":
							$global_net .= ($this->getConfig("other") == "true")? $net."\n" : "";
						break;
					}
					$ids = $IDsetting["ids"];
					$ids["fail2ban_whitelist"] = preg_replace('!\n+!', chr(10), $ids["fail2ban_whitelist"]."\n".$global_net);
				}
			}
			if($asfw["id_sync_fw"] == "enabled"){
				$this->FreePBX->Sysadmin->sync_fw($ids);
			}
			return true;
		case "addrfc":
			return $this->addRfcNetworks();
		case "addthishost":
			$thishost = $this->detectHost();
			$nets = $this->getConfig("networkmaps");
			if (!is_array($nets)) {
				$nets = array();
			}
			$nets[$thishost] = "trusted";
			$this->setConfig("networkmaps", $nets);
			return $this->runHook('addnetwork', array('trusted' => array($thishost)));
		case "addthisnetwork":
			$thisnet = $this->detectNetwork();
			$nets = $this->getConfig("networkmaps");
			if (!is_array($nets)) {
				$nets = array();
			}
			$nets[$thisnet] = "trusted";
			$this->setConfig("networkmaps", $nets);
			return $this->runHook('addnetwork', array('trusted' => array($thisnet)));
		case "updateinterfaces":
			// Extract our interfaces
			$ints = @json_decode($_REQUEST['ints'], true);
			if (!is_array($ints)) {
				throw new \Exception("Invalid interface data provided");
			}
			// Remove any previous notifications about interfaces (They'll be recreated
			// if they need to be)
			$this->Notifications()->delete('firewall', 'newint');
			$this->Notifications()->delete('firewall', 'trustedint');
			dbug($_REQUEST);
			return $this->runHook("updateinterfaces", $_REQUEST);
		case "updaterfw":
			// Ensure people don't accidentally allow traffic through when rfw is enabled
			$proto = $_REQUEST['proto'];
			$zones = array("internal");

			// Sanity check. 
			switch ($proto) {
			case "iax":
			case "pjsip":
			case "chansip":
				$this->setConfig($proto, $zones, "servicesettings");
			}
			return $this->setConfig($_REQUEST['proto'], ($_REQUEST['value'] == "true"), 'rfw');
		case "addtoblacklist":
			return $this->addToBlacklist(htmlentities(trim($_REQUEST['entry']), \ENT_QUOTES, 'UTF-8', false));
		case "removefromblacklist":
			return $this->removeFromBlacklist(htmlentities($_REQUEST['entry'], \ENT_QUOTES, 'UTF-8', false));
		case "setrejectmode":
			if ($_REQUEST['value'] != "reject") {
				return $this->setConfig("dropinvalid", true);
			} else {
				return $this->setConfig("dropinvalid", false);
			}

		// Custom firewall rules.
		case "addcustomrule":
			return $this->addCustomService(htmlentities(trim($_REQUEST['name']), \ENT_QUOTES, 'UTF-8', false), $_REQUEST['proto'], $_REQUEST['port']);
		case "editcustomrule":
			return $this->editCustomService($_REQUEST['id'], htmlentities($_REQUEST['name'], \ENT_QUOTES, 'UTF-8', false), $_REQUEST['proto'], $_REQUEST['port']);
		case "deletecustomrule":
			return $this->deleteCustomService($_REQUEST['id']);
		case "updatecustomzones":
			if (!isset($_REQUEST['zones'])) {
				$_REQUEST['zones'] = array();
			}
			return $this->setCustomServiceZones($_REQUEST['id'], $_REQUEST['zones']);

		// Attackers page
		case "getattackers":
			include __DIR__."/Attacks.class.php";
			$a = new Firewall\Attacks($this->getJiffies());
			$smart = $this->getSmartObj();
			return $a->getAllAttacks($smart->getRegistrations());
		case "delattacker":
			return $this->runHook("removeallblocks", array("unblock" => $_REQUEST['target']));

		// Advanced Settings
		case "updateadvanced":
			$pre = $this->getAdvancedSettings();
			$current = $this->setAdvancedSetting($_REQUEST['option'], $_REQUEST['val']);
			if($_REQUEST['option'] == "lefilter" && $pre[$_REQUEST['option']] != $_REQUEST['val']){
				$this->restartFirewall();
			}

			if($_REQUEST['option'] == "id_service" && $pre[$_REQUEST['option']] != $_REQUEST['val']){
				switch($_REQUEST['val']){
					case "enabled":
						$nt = \FreePBX::Notifications();
						$nt->delete("firewall", "1");
						$this->runHook("enable-fail2ban");
						$this->FreePBX->Sysadmin->runHook("fail2ban-stop");
						$this->FreePBX->Sysadmin->runHook("fail2ban-start");
					break;
					case "disabled":
						$nt = \FreePBX::Notifications();
						$nt->add_security("firewall", "1", _("Intrusion Detection Service Disabled"), _("Intrusion Detection Service will not be run on boot. Please, enable this service using the link below.") , "?display=firewall&page=advanced&tab=settings", $reset=true, $candelete=true);
						$this->runHook("disable-fail2ban");
						$this->FreePBX->Sysadmin->runHook("fail2ban-stop");
				}
			}
			return $current;

		// OOBE
		case "getoobequestion":
			include __DIR__."/OOBE.class.php";
			$o = new Firewall\OOBE($this);
			return $o->getQuestion();
		case "answeroobequestion":
			include __DIR__."/OOBE.class.php";
			$o = new Firewall\OOBE($this);
			return $o->answerQuestion();
		case "abortoobe":
			$this->setConfig("abortoobe", true);
			return true;
		case "restartoobe":
			$o = \FreePBX::OOBE()->getConfig("completed");
			if (!is_array($o)) {
				throw new \Exception("OOBE isn't an array");
			}
			unset ($o['firewall']);
			\FreePBX::OOBE()->setConfig("completed", $o);
			$this->setConfig("oobeanswered", array());
			$this->setConfig("abortoobe", false);
			return;

		default:
			throw new \Exception("Sad Panda - ".$_REQUEST['command']);
		}
	}

	// Manage Jiffies, for xt_recent
	public function getJiffies() {
		static $j = false;
		if (!$j) {
			include __DIR__."/Jiffies.class.php";
			$j = new Firewall\Jiffies;
		}
		$currentjiffies = $this->getConfig("currentjiffies");
		if (!$currentjiffies || $currentjiffies < 100) {
			$currentjiffies = $j->calcJiffies();
			$this->setConfig("currentjiffies", $currentjiffies);
		}
		$j->setKnownJiffies($currentjiffies);
		return $j;
	}

	public function restartFirewall($skip = "on"){
		// Disable FW
		$this->setConfig("status", false);

		// Stop FW
		$this->stopFirewall();

		// Start FW
		$this->preEnableFW($skip);
		$this->startFirewall();
	}

	public function preEnableFW($skip = "on"){
		if($skip == "on"){
			$thishost = $this->detectHost();
			$nets = $this->getConfig("networkmaps");
			if (!is_array($nets)) {
				$nets = array();
			}
			$nets[$thishost] = "trusted";
			$this->setConfig("networkmaps", $nets);			
		}
		$this->setConfig("status", true);
		touch("/etc/asterisk/firewall.enabled");
	}

	// Now comes the real code. Let's catch the POST and see if there's an action
	public function doConfigPageInit($display) {
		$action = $this->getReq('action');
		switch ($action) {
		case false:
			return;
		case 'enablefw':
			// Make sure that whoever enabled the firewall has access
			// to configure it!
			$this->preEnableFW();
			$this->runHook("firewall");
			return;
		case 'disablefw':
			if (!file_exists("/etc/asterisk/firewall.lock")) {
				@unlink("/etc/asterisk/firewall.enabled");
				$this->setConfig("status", false);
				return;
			} else {
				throw new \Exception(_("Firewall can not be disabled"));
			}
		case 'updateservices':
			if (!isset($_REQUEST['svc'])) {
				throw new \Exception("No services to update");
			}
			return $this->updateServices($_REQUEST['svc']);
		case 'enablerfw':
			$this->setConfig('responsivefw', true);
			return;
		case 'disablerfw':
			$this->setConfig('responsivefw', false);
			return;
		case 'intrusion_detection':
			return;
		default:
			throw new \Exception("Unknown action $action");
		}
	}

	public function getActionBar($request) {
		if ($this->getConfig("status")) {
			// Buttons for the main page
			// Note we have 'zones' here to capture any lingering FPBX Notifications which previously
			// were on the Zones page. 
			if (!isset($request['page']) || $request['page'] == "about" || $request['page'] == "zones") {
				return array(
					"savenets" => array('name' => 'savenets', 'style' => 'display: none', 'id' => 'savenets', 'value' => _("Save")),
					"delsel" => array('name' => 'delsel', 'style' => 'display: none', 'id' => 'delsel', 'value' => _("Delete Selected")),
					"saveints" => array('name' => 'saveints', 'style' => 'display: none', 'id' => 'saveints', 'value' => _("Update Interfaces")),
					"saveids" => array('name' => 'saveids', 'style' => 'display: none', 'id' => 'saveids', 'value' => _("Save Intrusion Detection")),
				);
			} elseif ($request['page'] === "services") {
				return array(
					// "defaults" => array('name' => 'defaults', 'id' => 'btndefaults', 'value' => _("Defaults")), // Unimplemented
					"reset" => array('name' => 'reset', 'id' => 'btnreset', 'value' => _("Reset")),
					"submit" => array('name' => 'submit', 'id' => 'btnsave', 'value' => _("Save")),
				);
			}
		}
	}

	public function getServices() {
		if (!self::$services) {
			include 'Services.class.php';
			self::$services = new Firewall\Services;
		}

		$retarr = array("core" => self::$services->getCoreServices(), "extra" => self::$services->getExtraServices(), "custom" => $this->getAllCustomServices());
		return $retarr;
	}

	public function getAllCustomServices() {
		return $this->getAll("customservices");
	}

	public function addCustomService($name, $proto, $ports) {
		// Generate a new id
		$id = $this->genUUID();
		// Make our custom service array
		$svc = array(
		   	"name" => $name,
			"defzones" => array("internal"),
			"descr" => "Custom Service",
			"custfw" => array("protocol" => $proto, "port" => $ports),
			"custid" => $id,
			"noreject" => true,
		);

		// And save it!
		$this->setConfig($id, $svc, "customservices");
		$this->setCustomServiceZones($id, array("internal"));
	}

	public function deleteCustomService($id) {
		$this->setConfig($id, false, "customservices");
		$this->setConfig($id, false, "servicesettings");
	}

	public function editCustomService($id, $name = false, $proto = false, $ports = false) {
		$svc = $this->getConfig($id, "customservices");

		if (!$svc) {
			throw new \Exception("Unknown custom service id $id");
		}

		// Update the rules with the new ones..
		if ($name) {
			$svc['name'] = $name;
		}

		if ($proto) {
			$svc['custfw']['protocol'] = $proto;
		}

		if ($ports) {
			$svc['custfw']['port'] = $ports;
		}

		// And save it.
		$this->setConfig($id, $svc, "customservices");
	}

	public function getCustomServiceZones($id) {
		$zones = $this->getConfig($id, "servicesettings");
		$retarr = array();
		if (is_array($zones)) {
			foreach ($zones as $zone) {
				$retarr[$zone] = $zone;
			}
		}
		return $retarr;
	}

	public function setCustomServiceZones($id, $zones = array()) {
		if (!is_array($zones)) {
			throw new \Exception("Don't know what I was given");
		}
		return $this->setConfig($id, $zones, "servicesettings");
	}

	// Update services.
	public function updateServices($svc) {

		$allsvcs = $this->getServices();
		$zones = $this->getZones();
		foreach ($allsvcs as $k => $arr) {
			foreach ($arr as $s) {
				if (is_array($s)) {
					// This is a custom service, not a known one, ignore.
					continue;
				}
				// Known service is $s - We were told about it in the post?
				if (!isset($svc[$s]) || !is_array($svc[$s])) {
					// Turned off!
					$this->setConfig($s, array(), "servicesettings");
					continue;
				}

				// Right, we have been told about this service. 
				$svcsetting = array();
				// Loop through the zones and see if they're enabled
				foreach ($zones as $z => $null) {
					if (isset($svc[$s][$z])) {
						$svcsetting[] = $z;
					}
				}

				// Now we can save that setting!
				$this->setConfig($s, $svcsetting, "servicesettings");
			}
		}
		return true;
	}

	public function getService($svc = false) {
		if (!$svc) {
			throw new \Exception("No service?");
		}
		if (!self::$services) {
			include 'Services.class.php';
			self::$services = new Firewall\Services;
		}

		$s = self::$services->getService($svc);
		$current = $this->getConfig($svc, "servicesettings");

		if ($current === false) {
			$current = $s['defzones'];
		}
		$s['zones'] = $current;
		return $s;
	}

	public function getZones() {
		static $zones = false;
		if (!$zones) {
			include 'Zones.class.php';
			$z = new Firewall\Zones;
			$zones = $z->getZones();
		}
		return $zones;
	}

	public function getInterfaces() {
		static $ints = false;
		if (!$ints) {
			include 'Network.class.php';
			$n = new Firewall\Network;
			$ints = $n->discoverInterfaces();
		}
		return $ints;
	}

	public function getZone($int) {
		static $ints = false;
		if (!$ints) {
			$ints = $this->getInterfaces();
		}

		// Is this a tunnel interface? That's always ALWAYS going to be
		// treated as 'internal' and is not configurable.
		if (strpos($int, "tun") === 0) {
			return "internal";
		}
		// Is this an alias? eg eth0:123? Then return the zone for the REAL interface.
		list ($realint) = explode(":", $int);

		// Make sure we HAVE a zone. Default to 'trusted'
		if (!isset($ints[$realint]['config']['ZONE'])) {
			$ints[$realint]['config']['ZONE'] = 'trusted';
		}

		return $ints[$realint]['config']['ZONE'];
	}

	public function getDriver() {

		if (!class_exists('\FreePBX\modules\Firewall\Driver')) {
			include __DIR__."/Driver.class.php";
		}

		$d = new Firewall\Driver;
		return $d->getDriver();
	}

	public function getSystemZones() {
		$d = $this->getDriver();
		return $d->getZonesDetails();
	}

	public function getNetworkDescriptions() {
		$desc = $this->getConfig("descriptions", "network");
		if (!is_array($desc)) {
			return array();
		} else {
			return $desc;
		}
	}
	
	public function detectNetwork() {
		$client = $_SERVER['REMOTE_ADDR'];
		// If this is an IPv4 address, treat it as a class C
		if (filter_var($client, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
			$ip = ip2long($client) & ip2long('255.255.255.0');
			return long2ip($ip)."/24";
		} elseif (filter_var($client, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
			// Grab the first 8 bytes, add zeros
			$prefix = unpack("H16", inet_pton($client));
			$map = $prefix[1]."0000000000000000";
			// Put it back into IPv6 format and give it back
			return inet_ntop(pack("H32", $map))."/64";
		} else {
			throw new \Exception("Unkown client $client");
		}
	}

	public function detectHost() {
		$ip = $_SERVER['REMOTE_ADDR'];
		if (filter_var($ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
			return "$ip/32";
		} elseif (filter_var($ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
			return "$ip/128";
		} else {
			throw new \Exception("REMOTE_ADDR didn't parse - $ip");
		}
	}

	// /////////////// //
	// Ajax Code below //
	// /////////////// //
	public function removeNetwork($net = false) {

		// If we've been asked to remove a hidden network,
		// make sure we remove the hidden tag, too
		$hidden = $this->getConfig("hiddennets");
		if (is_array($hidden) && isset($hidden[$net])) {
			unset($hidden[$net]);
			$this->setConfig("hiddennets", $hidden);
		}

		// Is it a host? We care about them differently.
		$hostmap = $this->getConfig("hostmaps");
		if (isset($hostmap[$net])) {
			// It's a host, not a network
			unset($hostmap[$net]);
			$this->setConfig("hostmaps", $hostmap);
		}

		// Now, grab what our zones should be...
		$nets = $this->getConfig("networkmaps");
		// Is this network part of a zone?
		if (!isset($nets[$net])) {
			return false;
		}
		$zone = $nets[$net];
		unset($nets[$net]);
		$this->setConfig("networkmaps", $nets);

		$desc = $this->getConfig("descriptions", "network");
		if (is_array($desc) && isset($desc[$net])) {
			unset($desc[$net]);
			$this->setConfig("descriptions", $desc, "network");
		}
		return $this->runHook("removenetwork", array("network" => $net, "zone" => $zone));
	}

	public function addNetworkToZone($net = false, $zone = false, $descr = "") {
		$net = trim($net);
		if (!$net) {
			// Someone clicked on an empty box..
			return;
		}
		// Is this a network?
		if (strpos($net, "/") !== false) {
			list($addr, $subnet) = explode("/", trim($net));
			if (!filter_var($addr, FILTER_VALIDATE_IP)) {
				throw new \Exception("Invalid IP '$addr'");
			}
		} else {
			$addr = trim($net);
			$subnet = false;
		}

		// Make sure this is a valid address
		if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			if (!$subnet) {
				$subnet = 32;
			}
			$ip = 4;
		} elseif (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			// Note: I hate this. You can't really determine the IP address of
			// an IPv6 host. IPv6 Security Extensions - which should be on for a
			// client - mandate the IP address changes.
			if (!$subnet) {
				$subnet = 128;
			}
			$ip = 6;
		} else {
			// It's probably a host. Add it to our host maps to care about later
			return $this->addHostToZone($net, $zone, $descr);
		}

		// Check subnet.. 
		$realsubnet = (int) $subnet;
		if ($ip == 4) {
			if ($realsubnet < 8 || $realsubnet > 32) {
				throw new \Exception("Invalid IPv4 subnet $realsubnet");
			}
		} else {
			if ($realsubnet < 8 || $realsubnet > 128) {
				throw new \Exception("Invalid IPv6 subnet $realsubnet");
			}
		}

		// Update the local cache
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}
		$nets["$addr/$subnet"] = $zone;
		$this->setConfig("networkmaps", $nets);

		// Update our description, if needed
		if ($descr) {
			$descriptions = $this->getConfig("descriptions", "network");
			if (!is_array($descriptions)) {
				$descriptions = array("$addr/$subnet" => $descr);
			} else {
				$descriptions["$addr/$subnet"] = $descr;
			}
			$this->setConfig("descriptions", $descriptions, "network");
		}
		$params = array($zone => array("$addr/$subnet"));
		return $this->runHook("addnetwork", $params);
	}

	public function addHostToZone($host, $zone, $descr = "") {
		$host = trim($host);
		if (!$host) {
			throw new \Exception("Can't add empty host");
		}

		$hosts = $this->getConfig("hostmaps");
		if (!is_array($hosts)) {
			$hosts = array();
		}
		$hosts[$host] = $zone;

		// Also add to network maps, for continuity.
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}
		$nets[$host] = $zone;
		$this->setConfig("networkmaps", $nets);

		// Update our description, if needed
		if ($descr) {
			$descriptions = $this->getConfig("descriptions", "network");
			if (!is_array($descriptions)) {
				$descriptions = array($host => $descr);
			} else {
				$descriptions[$host] = $descr;
			}
			$this->setConfig("descriptions", $descriptions, "network");
		}
		return $this->setConfig("hostmaps", $hosts);
	}

	public function changeNetworksZone($net, $zone, $descr = "") {
		$net = trim($net);
		if (!$net) {
			throw new \Exception("Can't add empty net");
		}

		// Get our current maps...
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}

		// Is this network part of a zone?
		if (!isset($nets[$net])) {
			throw new \Exception("Unknown network");
		}

		// Is it a host? We care about them differently.
		$hostmap = $this->getConfig("hostmaps");
		if (!empty($hostmap[$net])) {
			// It's a host, not a network
			$hostmap[$net] = $zone;
			$this->setConfig("hostmaps", $hostmap);
		}

		// Update and save the map...
		$nets[$net] = $zone;
		$this->setConfig("networkmaps", $nets);

		// Update our description, if needed
		if ($descr) {
			$descriptions = $this->getConfig("descriptions", "network");
			if (!is_array($descriptions)) {
				$descriptions = array($net => $descr);
			} else {
				$descriptions[$net] = $descr;
			}
			$this->setConfig("descriptions", $descriptions, "network");
		}

		// Disable hook
		// return $this->runHook("changenetwork", array("network" => $net, "newzone" => $zone));
	}

	// Add RFC1918 addresses to the trusted zone
	public function addRfcNetworks() {
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}

		$rfc = array ('192.168.0.0/16','172.16.0.0/12','10.0.0.0/8', 'fc00::/8', 'fd00::/8');
		foreach ($rfc as $n) {
			if (!isset($nets[$n])) {
				$nets[$n] = "trusted";
			}
		}
		$this->setConfig("networkmaps", $nets);

		return $this->runHook("addrfcnetworks");
	}

	public function getSmartObj() {
		static $sm = false;
		if (!$sm) {
			if (!class_exists('\FreePBX\modules\Firewall\Smart')) {
				include __DIR__."/Smart.class.php";
			}
			$sm = new Firewall\Smart($this->Database());
		}
		return $sm;
	}

	// Get all FreePBX services, as they are currently set
	// Note that this is **also** used by bin/getservices
	public function getSmartPorts() {
		$smart = $this->getSmartObj();
		return $smart->getAllPorts();
	}

	// Get Smart Firewall settings
	public function getSmartSettings() {
		$smart = $this->getSmartObj();
		return $smart->getSettings();
	}

	public function canRevert() {
		$ftok = ftok("/dev/shm/ipc_firewall", "a");
		$segment = shm_attach($ftok, 1048576, 0666); // Create/attach to 10k shared memory segment
		if (!shm_has_var($segment, 0)) { // Hasn't been used
			return false;
		}

		$settings = shm_get_var($segment, 0);
		if (isset($settings['timestamp']) && !isset($settings['confirmed'])) {
			return $settings['timestamp'];
		}

		return false;
	}

	public function isTrusted() {
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			return false;
		}

		// Discover the IP, and guess the network, of the remote client.
		$thisnet = $this->detectNetwork();
		$thishost = $this->detectHost();

		foreach ($nets as $n => $zone) {
			if ($zone !== "trusted") {
				continue;
			}

			if ($n === $thishost || $n === $thisnet) {
				return true;
			}

			if ($this->inRange($thishost, $n)) {
				return true;
			}
		}
		return false;
	}

	public function inRange($ipnet, $range) {
			$tmparr = explode("/", $range);
			$network = $tmparr[0];
			if (!isset($tmparr[1])) {
				$cidr = "32";
			} else {
				$cidr = $tmparr[1];
			}

			// Our Base CIDR is what is handed to us by detectHost, and from that
			// we can tell what we need to match against.
			list ($ip, $basecidr) = explode("/", $ipnet);

			// If it's a single host, it's a simple check.
			if ($cidr === "32" || $cidr === "128") {
				if ($network === $ip) {
					return true;
				} else {
					return false;
				}
			}

			// If its ipv6, this needs to be reworked, using net_pton to replace ip2long.
			if ($cirt === "128") {
				return false;
			} else {
				// IPv4: Convert our IPs to decimals for bitwise operations
				$ip_dec = ip2long($ip);
				$net_dec = ip2long($network);

				// Create our bitmap. This creates 1's of the CIDR, 00000000.00000000.00000000.11111111
				$wildcard = pow( 2, ( $basecidr - $cidr ) ) - 1;
				// This inverts it, so it's 11111111.11111111.11111111.00000000
				$netmask = ~ $wildcard;

				// Now, if the relevant bits of the NETWORK match the relevant bits of the HOST, we're good!
				return ( ( $ip_dec & $netmask ) == ( $net_dec & $netmask ) );
			}
	}

	public function rfcNetsAdded() {
		// Check to see if ALL the RFC1918 networks are added.
		$shouldbe = array ('192.168.0.0/16','172.16.0.0/12','10.0.0.0/8', 'fc00::/8', 'fd00::/8');
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			return false;
		}
		foreach ($shouldbe as $n) {
			if (!isset($nets[$n]) || $nets[$n] !== "trusted") {
				return false;
			}
		}
		return true;
	}

	public function thisHostAdded() {
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			return false;
		}
		$thishost = $this->detectHost();
		if (isset($nets[$thishost]) && $nets[$thishost] == "trusted") {
			return true;
		} else {
			return false;
		}
	}

	public function thisNetAdded() {
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			return false;
		}
		$thisnet = $this->detectNetwork();
		if (isset($nets[$thisnet]) && $nets[$thisnet] == "trusted") {
			return true;
		} else {
			return false;
		}
	}

	public function getBlacklist() {
		$hosts = array_keys($this->getAll("blacklist"));
		$smart = $this->getSmartObj();
		$retarr = array();
		foreach ($hosts as $h) {
			// Is this an IP address?
			list($test) = explode("/", $h);
			if (filter_var($test, \FILTER_VALIDATE_IP)) {
				$retarr[$h] = false;
				continue;
			} else {
				// Try a DNS lookup
				$retarr[$h] = $smart->lookup($h);
			}
		}
		return $retarr;
	}

	public function addToBlacklist($host) {
		// Make sure we can look this host up, and it's a valid thing to 
		// add to the blacklist.
		//
		$smart = $this->getSmartObj();
		// Is this a network? If it has a slash, assume it does.
		if (strpos($host, "/") !== false) {
			$rawnet = true;
			$trust = $smart->returnCidr($host);
		} else {
			$rawnet = false;
			$trust = $smart->lookup($host);
		}

		// If it's false, or empty, we couldn't validate it
		if (!$trust) {
			throw new \Exception("Can't validate $host");
		}

		// If it can, we can add it happily.
		// If this is a network, make sure we use the returnCidr value,
		// because that's actually correct.
		if ($rawnet) {
			$this->setConfig($trust, true, "blacklist");
		} else {
			$this->setConfig($host, true, "blacklist");
		}
	}

	public function removeFromBlacklist($host) {
		$this->setConfig($host, false, "blacklist");
	}

	public function genUUID() {
		// This generates a v4 GUID

		// Be cryptographically secure.
		$data = openssl_random_pseudo_bytes(16);

		$data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
		$data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

		return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
	}

	public function getAdvancedSettings() {
		$defaults = array("safemode" => "enabled", "masq" => "enabled", "lefilter" => "enabled", "customrules" => "disabled", "rejectpackets" => "disabled", "id_service" => "enabled", "id_sync_fw" => "legacy", "import_hosts" => "enabled");

		$settings = $this->getConfig("advancedsettings");
		if (!is_array($settings)) {
			$settings = $defaults;
			$this->setConfig("advancedsettings", $settings);
		}

		// Only return the keys we should return.
		$retarr = array();
		foreach ($defaults as $k => $v) {
			if (!isset($settings[$k])) {
				$retarr[$k] = $v;
			} else {
				$retarr[$k] = $settings[$k];
			}
		}
		return $retarr;
	}

	public function setAdvancedSetting($setting, $val) {
		$current = $this->getAdvancedSettings();
		if (!isset($current[$setting])) {
			throw new \Exception("$setting is not an advanced setting");
		}
		if ($current[$setting] !== trim($val)) {
			$current[$setting] = trim($val);
			$this->setConfig("advancedsettings", $current);
		}
		return $current;
	}

	public function addsyncjob(){
		$cron 		= \FreePBX::Cron();
		$fwc_path	= $this->FreePBX->Config->get("AMPSBIN")."/fwconsole";
		$cron->add("*/5 * * * * $fwc_path firewall sync > /dev/null 2>&1");
	}

	public function removesyncjob(){
		$cron 		= \FreePBX::Cron();
		$fwc_path	= $this->FreePBX->Config->get("AMPSBIN")."/fwconsole";
		$cron->remove("*/5 * * * * $fwc_path firewall sync > /dev/null 2>&1");
	}

	// Create a cron job that runs every 15 mins that tries to restart firewall
	// if it's not running when it should be.
	public function addCronJob() {
		$cron = \FreePBX::Cron();
		$hookfile = $this->get_astspooldir()."/incron/firewall.firewall";
		$enabledfile = $this->get_astetcdir()."/firewall.enabled";
		$line = "*/15 * * * * [ -e $enabledfile ] && touch $hookfile";
		$cron->add($line);
	}

	public function removeCronJob() {
		$cron = \FreePBX::Cron();
		$hookfile = $this->get_astspooldir()."/incron/firewall.firewall";
		$enabledfile = $this->get_astetcdir()."/firewall.enabled";
		$line = "*/15 * * * * [ -e $enabledfile ] && touch $hookfile";
		$cron->remove($line);
	}

	// Hooks
	public function getNameHooks($names) {
		$newnames = \FreePBX::Hooks()->processHooks($names);
		if ($newnames) {
			return $newnames;
		} else {
			return $names;
		}
	}
}

