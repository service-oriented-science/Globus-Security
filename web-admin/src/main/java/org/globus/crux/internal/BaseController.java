package org.globus.crux.internal;

import java.util.Collection;

import org.globus.crux.setup.ComponentFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/setup")
public class BaseController {
	@Autowired
	private CruxContainerModel model;
	

	@ModelAttribute("pipTypes")
	public Collection<ComponentFactory<?>> populateAuthorizationEngineTypes() {
		return model.getPipFactories();
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView handleRequest(
			@ModelAttribute("pipTypes") Collection<ComponentFactory<?>> pipFactories)
			throws Exception {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("crux_setup");
		StringBuilder builder = new StringBuilder();
		for (ComponentFactory<?> compFact : pipFactories) {
			builder.append(compFact.getMetadata().getName() + " ");
		}
		mav.addObject("message", builder.toString());
		return mav;
	}
}
