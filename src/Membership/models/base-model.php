<?php

namespace Membership;

class BaseModel
{

    protected $db = null;
    protected $logger = null;

    /**
     * @param \PDO $db
     * @param \Monolog\Logger $logger
     */
    public function __construct($db, $logger = null)
    {
        $this->db = $db;
        $this->logger = $logger;
    }

    /**
     * @param string $msg
     * @param array $context
     */
    protected function logDebug($msg, $context = array())
    {
        if (!empty($this->logger)) {
            $this->logger->addDebug($msg, $context);
        }
    }
}