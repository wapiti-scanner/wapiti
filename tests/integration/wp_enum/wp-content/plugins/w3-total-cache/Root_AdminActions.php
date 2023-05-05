<?php
namespace W3TC;

class Root_AdminActions {
	public function __construct() {
	}

	public function execute( $action ) {
		$handler_class = $this->_get_handler( $action );
		$handler_class_fullname = '\\W3TC\\' . $handler_class;
		$handler_object = new $handler_class_fullname;

		$action_details = explode( '~', $action );

		if ( count( $action_details ) > 1 ) {
			// action is in form "action~parameter"
			$method = $action_details[0];
			if ( method_exists( $handler_object, $method ) ) {
				$handler_object->$method( $action_details[1] );
				return;
			}
		} else {
			// regular action
			if ( method_exists( $handler_object, $action ) ) {
				$handler_object->$action();
				return;
			}
		}

		throw new \Exception( sprintf( __( 'action %s does not exist' ), $action ) );
	}

	public function exists( $action ) {
		$handler =  $this->_get_handler( $action );
		return $handler != '';
	}

	private function _get_handler( $action ) {
		static $handlers = null;
		if ( is_null( $handlers ) ) {
			$handlers = array(
				'boldgrid' => 'Generic_WidgetBoldGrid_AdminActions',
				'cdn_google_drive' => 'Cdn_GoogleDrive_AdminActions',
				'cdn' => 'Cdn_AdminActions',
				'config' => 'Generic_AdminActions_Config',
				'default' => 'Generic_AdminActions_Default',
				'extensions' => 'Extensions_AdminActions',
				'flush' => 'Generic_AdminActions_Flush',
				'licensing' => 'Licensing_AdminActions',
				'support' => 'Support_AdminActions',
				'test' => 'Generic_AdminActions_Test',
				'ustats' => 'UsageStatistics_AdminActions'
			);
			$handlers = apply_filters( 'w3tc_admin_actions', $handlers );
		}

		if ( $action == 'w3tc_save_options' )
			return $handlers['default'];

		$candidate_prefix = '';
		$candidate_class = '';

		foreach ( $handlers as $prefix => $class ) {
			$v1 = "w3tc_$prefix";
			$v2 = "w3tc_save_$prefix";

			if ( substr( $action, 0, strlen( $v1 ) ) == $v1 ||
				substr( $action, 0, strlen( $v2 ) ) == $v2 ) {
				if ( strlen( $candidate_prefix ) < strlen( $prefix ) ) {
					$candidate_class = $class;
					$candidate_prefix = $prefix;
				}
			}
		}

		return $candidate_class;
	}
}
