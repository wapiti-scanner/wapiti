import selectors from '../api';

describe( 'apiSelectors', () => {
	const fixtures = {
		emptyObjectAPIState: {
			API: {},
		},
		dummyValueAPIState: {
			API: {
				dummyItem: 'dummyValue',
			},
		},
	};

	describe( 'getAPIRoot()', () => {
		it.each( [
			{
				state: fixtures.emptyObjectAPIState,
				expected: null,
			},
			{
				state: fixtures.dummyValueAPIState,
				expected: null,
			},
			{
				state: {
					API: {
						WP_API_root: 'https://wordpress.com/wp-json/',
					},
				},
				expected: 'https://wordpress.com/wp-json/',
			},
		] )( 'should return WP_API_root value if passed, null otherwise', ( { state, expected } ) => {
			const output = selectors.getAPIRoot( state );
			expect( output ).toBe( expected );
		} );
	} );

	describe( 'getAPINonce()', () => {
		it.each( [
			{
				state: fixtures.emptyObjectAPIState,
				expected: null,
			},
			{
				state: fixtures.dummyValueAPIState,
				expected: null,
			},
			{
				state: {
					API: {
						WP_API_nonce: 123456,
					},
				},
				expected: 123456,
			},
		] )( 'should return WP_API_nonce value if passed, null otherwise', ( { state, expected } ) => {
			const output = selectors.getAPINonce( state );
			expect( output ).toBe( expected );
		} );
	} );

	describe( 'getRegistrationNonce()', () => {
		it.each( [
			{
				state: fixtures.emptyObjectAPIState,
				expected: null,
			},
			{
				state: fixtures.dummyValueAPIState,
				expected: null,
			},
			{
				state: {
					API: {
						registrationNonce: 123456,
					},
				},
				expected: 123456,
			},
		] )(
			'should return registrationNonce value if passed, null otherwise',
			( { state, expected } ) => {
				const output = selectors.getRegistrationNonce( state );
				expect( output ).toBe( expected );
			}
		);
	} );
} );
