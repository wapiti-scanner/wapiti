import API from '../api';

describe( 'reducer', () => {
	describe( 'API', () => {
		test( 'should return the initial state when undefined state is passed', () => {
			expect( API( undefined, {} ) ).toEqual( {} );
		} );
	} );
} );
