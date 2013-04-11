<?php

class dnsTXTresult extends dnsResult
{
    private $record;
    
    public function __construct($record) 
    {
        $this->setRecord($record);
    }
    
    public function setRecord($record)
    {
        $this->record = $record;
    }
    
    public function getRecord()
    {
        return $this->record;
    }
}
