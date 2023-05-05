import jetpackStatus from '../jetpack-status';

describe( 'reducer', () => {
	describe( 'jetpackStatus', () => {
		test( 'should return the initial state when undefined state is passed', () => {
			expect( jetpackStatus( undefined, {} ) ).toEqual( {} );
		} );
	} );
} );
