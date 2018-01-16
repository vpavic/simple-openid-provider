package io.github.vpavic.oauth2.subject;

import javax.servlet.http.HttpServletRequest;

import com.nimbusds.oauth2.sdk.id.Subject;

/**
 * A strategy for resolving {@link Subject} from request.
 *
 * @author Vedran Pavic
 */
public interface SubjectResolver {

	Subject resolveSubject(HttpServletRequest request);

}
