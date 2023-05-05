/* global MilestoneConfig */

var Milestone = ( function () {
	var Milestone = function ( args ) {
		var widget_content = document.getElementById( args.content_id ),
			id = args.id,
			refresh = args.refresh * 1000;

		this.timer = function () {
			var instance = this;
			var xhr = new XMLHttpRequest();

			xhr.onload = function () {
				var response = JSON.parse( xhr.responseText ),
					httpCheck = xhr.status >= 200 && xhr.status < 300,
					responseCheck =
						'undefined' !== typeof response.message && 'undefined' !== typeof response.refresh;

				if ( httpCheck && responseCheck ) {
					var countdownElement = widget_content.querySelector( '.milestone-countdown' );

					countdownElement.outerHTML = response.message;
					refresh = response.refresh * 1000;

					if ( ! refresh ) {
						return;
					}

					setTimeout( function () {
						instance.timer();
					}, refresh );
				}
			};

			xhr.open( 'GET', MilestoneConfig.api_root + 'jetpack/v4/widgets/' + id );
			xhr.send();
		};

		if ( refresh > 0 ) {
			this.timer();
		}
	};
	return function ( args ) {
		return new Milestone( args );
	};
} )();

( function () {
	var i,
		MilestoneInstances = {};

	if ( typeof MilestoneConfig === 'undefined' ) {
		return;
	}

	for ( i = 0; i < MilestoneConfig.instances.length; i++ ) {
		MilestoneInstances[ i ] = new Milestone( MilestoneConfig.instances[ i ] );
	}
} )();
