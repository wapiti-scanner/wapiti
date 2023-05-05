import selectors from '../jetpack-status';

describe( 'siteDataSelectors', () => {
	describe( 'getCalypsoSlug()', () => {
		it( 'should return empty object when jetpackStatus is an empty object', () => {
			const state = {
				jetpackStatus: {},
			};
			const output = selectors.getCalypsoSlug( state );
			expect( output ).toEqual( {} );
		} );

		it( 'should return empty object when does not include a calypsoSlug', () => {
			const state = {
				jetpackStatus: {
					dummyItem: 'dummyValue',
				},
			};
			const output = selectors.getCalypsoSlug( state );
			expect( output ).toEqual( {} );
		} );

		it( 'should return calypsoSlug when includes jetpackStatus with calypsoSlug', () => {
			const state = {
				jetpackStatus: {
					calypsoSlug: 'wordpress.com',
				},
			};
			const output = selectors.getCalypsoSlug( state );
			expect( output ).toBe( 'wordpress.com' );
		} );
	} );
} );
