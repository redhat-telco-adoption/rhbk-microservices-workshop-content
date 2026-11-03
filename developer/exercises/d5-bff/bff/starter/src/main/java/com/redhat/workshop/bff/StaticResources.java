package com.redhat.workshop.bff;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.ResourceHandlerRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.http.CacheControl;
import java.time.Duration;

@Configuration
public class StaticResources implements WebFluxConfigurer {
  @Override
  public void addResourceHandlers(ResourceHandlerRegistry registry) {
    registry.addResourceHandler("/assets/**").addResourceLocations("classpath:/static/assets/")
        .setCacheControl(CacheControl.maxAge(Duration.ofDays(365)).cachePublic().immutable());
    registry.addResourceHandler("/*.js", "/*.css", "/*.svg", "/*.png", "/*.ico")
        .addResourceLocations("classpath:/static/")
        .setCacheControl(CacheControl.maxAge(Duration.ofDays(365)).cachePublic().immutable());
  }
}
