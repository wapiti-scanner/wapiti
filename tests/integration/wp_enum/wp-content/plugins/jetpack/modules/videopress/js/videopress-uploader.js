/* globals plupload, pluploadL10n, error */
window.wp = window.wp || {};

( function ( wp ) {
	var VideoPress = {
		originalOptions: {},

		/**
		 * This is the standard uploader response handler.
		 */
		handleStandardResponse: function ( response, file ) {
			if ( ! _.isObject( response ) || _.isUndefined( response.success ) ) {
				return error( pluploadL10n.default_error, null, file );
			} else if ( ! response.success ) {
				return error( response.data && response.data.message, response.data, file );
			}

			return response;
		},

		/**
		 * Handle response from the WPCOM Rest API.
		 */
		handleRestApiResponse: function ( response, file ) {
			if ( response.media.length !== 1 ) {
				return error( pluploadL10n.default_error, null, file );
			}

			var media = response.media[ 0 ],
				mimeParts = media.mime_type.split( '/' ),
				data = {
					alt: '',
					author: media.author_ID || 0,
					authorName: '',
					caption: '',
					compat: { item: '', meta: '' },
					date: media.date || '',
					dateFormatted: media.date || '',
					description: media.description || '',
					editLink: '',
					filename: media.file || '',
					filesizeHumanReadable: '',
					filesizeInBytes: '',
					height: media.height,
					icon: media.icon || '',
					id: media.ID || '',
					link: media.URL || '',
					menuOrder: 0,
					meta: false,
					mime: media.mime_type || '',
					modified: 0,
					name: '',
					nonces: { update: '', delete: '', edit: '' },
					orientation: '',
					sizes: undefined,
					status: '',
					subtype: mimeParts[ 1 ] || '',
					title: media.title || '',
					type: mimeParts[ 0 ] || '',
					uploadedTo: 1,
					uploadedToLink: '',
					uploadedToTitle: '',
					url: media.URL || '',
					width: media.width,
					success: '',
					videopress: {
						guid: media.videopress_guid || null,
						processing_done: media.videopress_processing_done || false,
					},
				};

			response.data = data;

			return response;
		},

		/**
		 * Make sure that all of the original variables have been reset, so the uploader
		 * doesn't try to go to VideoPress again next time.
		 *
		 * @param up
		 */
		resetToOriginalOptions: function ( up ) {
			if ( typeof VideoPress.originalOptions.url !== 'undefined' ) {
				up.setOption( 'url', VideoPress.originalOptions.url );
				delete VideoPress.originalOptions.url;
			}

			if ( typeof VideoPress.originalOptions.multipart_params !== 'undefined' ) {
				up.setOption( 'multipart_params', VideoPress.originalOptions.multipart_params );
				delete VideoPress.originalOptions.multipart_params;
			}

			if ( typeof VideoPress.originalOptions.file_data_name !== 'undefined' ) {
				up.setOption( 'file_data_name', VideoPress.originalOptions.file_data_name );
				delete VideoPress.originalOptions.file_data_name;
			}
		},
	};

	if ( typeof wp.Uploader !== 'undefined' ) {
		var media = wp.media;

		/**
		 * A plupload code specifically for videopress failures.
		 *
		 * @type {string}
		 */
		plupload.VIDEOPRESS_TOKEN_FAILURE = 'VP_TOKEN_FAILURE';

		/**
		 * Adds a filter that checks all files to see if they are videopress files and if they are
		 * it will download extra metadata for them.
		 */
		plupload.addFileFilter( 'videopress_check_uploads', function ( maxSize, file, cb ) {
			var mimeParts = file.type.split( '/' );
			var self = this;

			if ( mimeParts[ 0 ] === 'video' ) {
				media
					.ajax( 'videopress-get-upload-token', { async: false, data: { filename: file.name } } )
					.done( function ( response ) {
						file.videopress = response;
						cb( true );
					} )
					.fail( function ( response ) {
						self.trigger( 'Error', {
							code: plupload.VIDEOPRESS_TOKEN_FAILURE,
							message: plupload.translate(
								'Could not get the VideoPress token needed for uploading'
							),
							file: file,
							response: response,
						} );
						cb( false );
					} );
			} else {
				// Handles the normal max_file_size functionality.
				var undef;

				// Invalid file size
				if ( file.size !== undef && maxSize && file.size > maxSize ) {
					this.trigger( 'Error', {
						code: plupload.FILE_SIZE_ERROR,
						message: plupload.translate( 'File size error.' ),
						file: file,
					} );
					cb( false );
				} else {
					cb( true );
				}
			}
		} );
	}

	wp.VideoPress = VideoPress;
} )( window.wp );
