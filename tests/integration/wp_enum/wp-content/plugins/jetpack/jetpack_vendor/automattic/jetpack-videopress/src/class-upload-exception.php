<?php
/**
 * VideoPress Uploader Exception
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

/**
 * VideoPress Uploader Exception class
 */
class Upload_Exception extends \Exception {
	const ERROR_INVALID_ATTACHMENT_ID   = 0;
	const ERROR_FILE_NOT_FOUND          = 1;
	const ERROR_MIME_TYPE_NOT_SUPPORTED = 2;
	const ERROR_MALFORMED_FILE          = 3;
}
