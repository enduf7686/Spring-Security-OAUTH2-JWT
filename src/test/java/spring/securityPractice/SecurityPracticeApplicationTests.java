package spring.securityPractice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

@SpringBootTest
class SecurityPracticeApplicationTests {

	@Autowired
	ApplicationContext ac;

	@Test
	void contextLoads() {
		String[] beanDefinitionNames = ac.getBeanDefinitionNames();
		for (String name : beanDefinitionNames) {
			System.out.println("beanName = " + name + ", " + ac.getBean(name).getClass());
		}
	}

}
