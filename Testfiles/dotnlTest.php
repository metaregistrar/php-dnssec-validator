<?php
include_once("../validate.php");


class dotnlTest extends PHPUnit_Framework_TestCase
{

    /**
     * Sets up the fixture, for example, opens a network connection.
     * This method is called before a test is executed.
     */
    protected function setUp()
    {
    }

    /**
     * Tears down the fixture, for example, closes a network connection.
     * This method is called after a test is executed.
     */
    protected function tearDown()
    {
    }

    public function test_Success_Metaregistrarnl()
    {
        $domainname = 'metaregistrar.nl';
        $this->assertTrue(validateDomain($domainname));
    }

    public function test_Success_Sidnnl()
    {
        $domainname = 'sidn.nl';
        $this->assertTrue(validateDomain($domainname));
    }
    
    
}