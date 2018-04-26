package io.github.vpavic.oauth2.util;

public final class StringUtils {

	private StringUtils() {

	}

	public static boolean isBlank(final CharSequence cs) {
		if (cs == null || cs.length() == 0) {
			return true;
		}
		for (int i = 0; i < cs.length(); i++) {
			if (!Character.isWhitespace(cs.charAt(i))) {
				return false;
			}
		}
		return true;
	}

}
