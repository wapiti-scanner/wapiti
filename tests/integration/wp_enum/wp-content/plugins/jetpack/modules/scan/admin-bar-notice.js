( function ( localized ) {
	function ready( fn ) {
		if ( document.readyState != 'loading' ) {
			fn();
		} else {
			document.addEventListener( 'DOMContentLoaded', fn );
		}
	}

	function fetch_scan_treats_and_add_link() {
		var xhrRequest = new XMLHttpRequest();
		xhrRequest.open( 'GET', localized.scan_endpoint, true );
		xhrRequest.onload = function () {
			if ( this.status == 200 ) {
				// Success!
				var body = JSON.parse( this.response );
				if ( body && body.data ) {
					var apiResponse = JSON.parse( body.data );
					var numberOfThreats =
						apiResponse.threats && apiResponse.threats.length ? apiResponse.threats.length : 0;
					update_threats_link( numberOfThreats );
				} else {
					update_threats_link( 0 );
				}
			} else {
				update_threats_link( 0 );
			}
		};
		xhrRequest.setRequestHeader( 'X-WP-Nonce', localized.nonce );
		xhrRequest.send();
	}

	ready( function () {
		fetch_scan_treats_and_add_link();
	} );

	function update_threats_link( numberOfThreats ) {
		var element = document.getElementById( 'wp-admin-bar-jetpack-scan-notice' );
		if ( ! element ) {
			return;
		}

		if ( ! numberOfThreats ) {
			element.parentNode.removeChild( element );
			return;
		}

		var textLabel = numberOfThreats == 1 ? localized.singular : localized.multiple;
		element.innerHTML =
			'<a href="' + localized.scan_dashboard_url + '" class="ab-item">' + textLabel + '</a>';
	}
} )( window.Jetpack_Scan );
