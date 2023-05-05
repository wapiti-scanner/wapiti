<?php
namespace W3TC;



class Extensions_AdminActions {
	function w3tc_extensions_activate() {
		$config = Dispatcher::config();

		$extension = Util_Request::get_string( 'w3tc_extensions_activate' );
		$ext = Extensions_Util::get_extension( $config, $extension );

		if ( !is_null( $ext ) ) {
			if ( Extensions_Util::activate_extension( $extension, $config ) ) {
				Util_Admin::redirect_with_custom_messages2( array(
						'notes' => array( sprintf(
								__( 'Extension <strong>%s</strong> has been successfully activated.',
									'w3-total-cache' ),
								$ext['name']
							) )
					) );
				return;
			}
		}

		Util_Admin::redirect( array() );
	}
}
