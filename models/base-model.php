<?php

namespace Membership;

class BaseModel {
	
	protected $db = null;
	protected $logger = null;
	
	public function __construct($db, $logger = null){
		$this->db = $db;
		$this->logger = $logger;
	}
	
	protected function logDebug($msg, $context = array()){
		if(!empty($this->logger)){
			$this->logger->addDebug($msg, $context);
		}
	}
}