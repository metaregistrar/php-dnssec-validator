<?php

class dnsAresult extends dnsResult
{
    private $ipv4;
    
    function __construct($ip)
    {
        $this->setIpv4($ip);
    }
    
    public function setIpv4($ip)
    {
        $this->ipv4 = $ip;
    }
    
    public function getIpv4()
    {
        return $this->ipv4;
    }
}
