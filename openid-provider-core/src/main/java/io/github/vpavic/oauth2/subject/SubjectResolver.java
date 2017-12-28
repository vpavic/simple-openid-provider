package io.github.vpavic.oauth2.subject;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * A strategy for resolving {@link Subject} from request.
 *
 * @author Vedran Pavic
 */
public interface SubjectResolver {

	Subject resolveSubject(ServletWebRequest request);

}
