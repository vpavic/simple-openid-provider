package io.github.vpavic.oauth2.util;

import java.util.Collection;

public final class SetUtils {

	private SetUtils() {

	}

	public static boolean isEqualSet(final Collection<?> set1, final Collection<?> set2) {
		if (set1 == set2) {
			return true;
		}
		if (set1 == null || set2 == null || set1.size() != set2.size()) {
			return false;
		}
		return set1.containsAll(set2);
	}

}
