
	
	class csrf {

		public static function init() {
			if (!isset($_SESSION['csrf_token']) || (isset($_SESSION['csrf_token']) && !$_SESSION['csrf_token']))
				$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
		}

		public static function validate() {
			$return = array(
				'success'   => false,
				'msg'       => 'Unknown CSRF Error',
			);

			init_csrf();

			$headers = apache_request_headers();

			if (isset($headers['Csrftoken']))
				$csrf_token = $headers['Csrftoken'];
			elseif (isset($headers['CsrfToken']))
				$csrf_token = $headers['CsrfToken'];
			elseif (isset($headers['csrftoken']))
				$csrf_token = $headers['csrftoken'];
			else
				$csrf_token = false;

			if ($csrf_token) {
				if (!hash_equals($csrf_token, $_SESSION['csrf_token'])) {
					$return['success'] = false;
					$return['msg']     = 'Wrong CSRF token.';
				} else
					$return['success'] = true;
			} else {
				$return['success']  = false;
				$return['msg']      = 'No CSRF token.';
			}

			return $return;
		}
		
	}
