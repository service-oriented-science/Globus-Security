package org.globus.crux.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.globus.crux.setup.ComponentFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/pips")
public class PIPS {

	Logger logger = LoggerFactory.getLogger(getClass());
	@Autowired
	private CruxContainerModel model;

	@ModelAttribute("pipTypes")
	public Collection<ComponentFactory<?>> populateAuthorizationEngineTypes() {
		List<ComponentFactory<?>> facts = new ArrayList<ComponentFactory<?>>();
		facts.addAll(model.getAuthorizationEngineFactories());
		return facts;
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView getPips(
			@ModelAttribute("pipTypes") Collection<ComponentFactory<?>> pipFactories)
			throws Exception {
		ModelAndView mav = new ModelAndView();
		mav.setViewName("pips");
		mav.addObject(pipFactories);
		logger.info("processing pips");
		return mav;
	}

}
