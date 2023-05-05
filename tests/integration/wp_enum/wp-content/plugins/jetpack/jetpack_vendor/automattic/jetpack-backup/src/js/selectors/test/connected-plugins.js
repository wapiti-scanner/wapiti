import selectors from '../connected-plugins';

describe( 'connectedPluginsSelectors', () => {
	describe( 'getConnectedPlugins()', () => {
		it( 'should return empty object when connectedPlugins is undefined', () => {
			const state = {
				connectedPlugins: undefined,
			};
			const output = selectors.getConnectedPlugins( state );
			expect( output ).toEqual( [] );
		} );

		it( 'should return connectedPlugins content when defined', () => {
			const state = {
				connectedPlugins: {
					'jetpack-backup': {
						name: 'Jetpack Backup',
						url_info: 'https://jetpack.com/jetpack-backup',
					},
				},
			};
			const output = selectors.getConnectedPlugins( state );
			expect( output ).toEqual( {
				'jetpack-backup': {
					name: 'Jetpack Backup',
					url_info: 'https://jetpack.com/jetpack-backup',
				},
			} );
		} );
	} );
} );
