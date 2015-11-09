<?php
//##copyright##

class iaCaptcha extends abstractUtil
{
	// Get a key from http://www.capinno.ru
	protected $_publicKey = '';
	protected $_privateKey = '';

	protected $_theme;

	protected $_error;


	public function __construct()
	{
		parent::init();

		require_once dirname(__FILE__) . IA_DS . '..' . IA_DS . 'capinno' . IA_DS . 'cap4a_lib.php';

		$this->_publicKey = $this->iaCore->get('capinno_publickey');
		$this->_privateKey = $this->iaCore->get('capinno_privatekey');
		$this->_theme = $this->iaCore->get('capinno_theme');
	}

	public function getImage()
	{
		if (!$this->_publicKey || !$this->_privateKey)
		{
			return iaLanguage::get('capinno_set_configuration');
		}

		$return = <<<CODE
<script type="text/javascript" src="http://part.cap4a.com/js/challenge.js?k={$this->_publicKey}"></script>
<noscript>
	<iframe src="http://part.cap4a.com/noscript.jsp?k={$this->_publicKey}" height="300" width="500" frameborder="0"></iframe><br>
	<textarea name="cap4a_challenge_field" rows="3" cols="40"></textarea>
	<input type="hidden" name="cap4a_response_field" value="manual_challenge">
</noscript>
CODE;

		return $return;
	}

	public function validate()
	{
		$response = cap4a_check_answer("", $this->_privateKey, $_SERVER['REMOTE_ADDR'], $_POST['cap4a_challenge_field'], $_POST['cap4a_response_field']);

		if ($response->is_valid)
		{
			return true;
		}

		return false;
	}

	public function getPreview()
	{
		return $this->getImage();
	}
}