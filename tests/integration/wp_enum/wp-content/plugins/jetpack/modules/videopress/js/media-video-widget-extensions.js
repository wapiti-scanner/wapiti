window.wp = window.wp || {};

( function ( wp ) {
	if ( wp.mediaWidgets ) {
		// Over-ride core media_video#mapMediaToModelProps to set the url based upon videopress_guid if it exists.
		wp.mediaWidgets.controlConstructors.media_video.prototype.mapMediaToModelProps = ( function (
			originalMapMediaToModelProps
		) {
			return function ( mediaFrameProps ) {
				var newProps, originalProps, videoPressGuid;
				originalProps = originalMapMediaToModelProps.call( this, mediaFrameProps );
				newProps = _.extend( {}, originalProps );

				// API response on new media will have the guid at videopress.guid.
				if ( mediaFrameProps.videopress && mediaFrameProps.videopress.guid ) {
					videoPressGuid = mediaFrameProps.videopress.guid;
				}

				// Selecting an existing VideoPress file will have the guid at .videopress_guid[ 0 ].
				if (
					! videoPressGuid &&
					mediaFrameProps.videopress_guid &&
					mediaFrameProps.videopress_guid.length
				) {
					videoPressGuid = mediaFrameProps.videopress_guid[ 0 ];
				}

				if ( videoPressGuid ) {
					newProps = _.extend( {}, originalProps, {
						url: 'https://videopress.com/v/' + videoPressGuid,
						attachment_id: 0,
					} );
				}
				return newProps;
			};
		} )( wp.mediaWidgets.controlConstructors.media_video.prototype.mapMediaToModelProps );

		// Over-ride core media_video#isHostedVideo() to add support for videopress oembed urls.
		wp.mediaWidgets.controlConstructors.media_video.prototype.isHostedVideo = ( function (
			originalIsHostedVideo
		) {
			return function ( url ) {
				var parsedUrl = document.createElement( 'a' );
				parsedUrl.href = url;
				if ( 'videopress.com' === parsedUrl.hostname ) {
					return true;
				}
				return originalIsHostedVideo.call( this, url );
			};
		} )( wp.mediaWidgets.controlConstructors.media_video.prototype.isHostedVideo );
	}
} )( window.wp );
