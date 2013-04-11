<?php

class dnsNSresult extends dnsResult
{
    private $nameserver;
    
    public function __construct($ns)
    {
        $this->setNameserver($ns);
    }
    
    public function setNameserver($server)
    {
        $this->nameserver = $server;
    }
    
    public function getNameserver()
    {
        return $this->nameserver;
    }
}
