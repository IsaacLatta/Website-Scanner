from dataclasses import dataclass
from typing import List, Literal
from scanner.modules.error.signature import Signature

FrameworkCategory = Literal[
    "runtime",
    "backend",
    "frontend",
    "fullstack",
    "cms",
    "static_site",
    "library",
]

FRAMEWORK_SIGNATURES: List[Signature] = [
    Signature(
        display_name="Node.js",
        category="runtime",
        aliases=["node.js", "nodejs", "node"],
    ),
    Signature(
        display_name="React",
        category="frontend",
        aliases=["react", "reactjs", "react.js"],
    ),
    # Signature(
    #     display_name="jQuery",
    #     category="library",
    #     aliases=["jquery"],
    # ),
    Signature(
        display_name="Next.js",
        category="fullstack",
        aliases=["next.js", "nextjs", "next js", "next"],
    ),
    Signature(
        display_name="Express",
        category="backend",
        aliases=["express", "express.js", "expressjs"],
    ),
    Signature(
        display_name="Angular",
        category="frontend",
        aliases=["angular"],
    ),
    Signature(
        display_name="ASP.NET Core",
        category="backend",
        aliases=["asp.net core", "aspnetcore", "asp net core"],
    ),
    Signature(
        display_name="Vue.js",
        category="frontend",
        aliases=["vue", "vue.js", "vuejs"],
    ),
    Signature(
        display_name="ASP.NET",
        category="backend",
        aliases=["asp.net", "aspnet", "asp net"],
    ),
    Signature(
        display_name="Flask",
        category="backend",
        aliases=["flask"],
    ),
    Signature(
        display_name="Spring Boot",
        category="backend",
        aliases=["spring boot", "spring-boot"],
    ),
    Signature(
        display_name="Django",
        category="backend",
        aliases=["django"],
    ),
    Signature(
        display_name="WordPress",
        category="cms",
        aliases=["wordpress", "wp"],
    ),
    Signature(
        display_name="FastAPI",
        category="backend",
        aliases=["fastapi", "fast api"],
    ),
    Signature(
        display_name="Laravel",
        category="backend",
        aliases=["laravel"],
    ),
    Signature(
        display_name="AngularJS",
        category="frontend",
        aliases=["angularjs", "angular.js", "angular 1", "angular 1.x"],
    ),
    Signature(
        display_name="Svelte",
        category="frontend",
        aliases=["svelte"],
    ),
    Signature(
        display_name="NestJS",
        category="backend",
        aliases=["nestjs", "nest.js", "nest js", "nest"],
    ),
    Signature(
        display_name="Blazor",
        category="frontend",
        aliases=["blazor"],
    ),
    Signature(
        display_name="Ruby on Rails",
        category="backend",
        aliases=["ruby on rails", "rails"],
    ),
    Signature(
        display_name="Nuxt.js",
        category="fullstack",
        aliases=["nuxt", "nuxt.js", "nuxtjs"],
    ),
    Signature(
        display_name="Htmx",
        category="library",
        aliases=["htmx"],
    ),
    Signature(
        display_name="Symfony",
        category="backend",
        aliases=["symfony"],
    ),
    Signature(
        display_name="Astro",
        category="static_site",
        aliases=["astro"],
    ),
    Signature(
        display_name="Fastify",
        category="backend",
        aliases=["fastify"],
    ),
    Signature(
        display_name="Deno",
        category="runtime",
        aliases=["deno"],
    ),
    Signature(
        display_name="Phoenix",
        category="backend",
        aliases=["phoenix"],
    ),
    Signature(
        display_name="Drupal",
        category="cms",
        aliases=["drupal"],
    ),
    Signature(
        display_name="Strapi",
        category="cms",
        aliases=["strapi"],
    ),
    Signature(
        display_name="CodeIgniter",
        category="backend",
        aliases=["codeigniter", "code igniter"],
    ),
    Signature(
        display_name="Gatsby",
        category="static_site",
        aliases=["gatsby", "gatsby.js", "gatsbyjs"],
    ),
    Signature(
        display_name="Remix",
        category="fullstack",
        aliases=["remix"],
    ),
    # Signature( # Noisy, many false positives
    #     display_name="Solid.js",
    #     category="frontend",
    #     aliases=["solid", "solid.js", "solidjs"],
    # ),
    Signature(
        display_name="Yii 2",
        category="backend",
        aliases=["yii 2", "yii2", "yii"],
    ),
    Signature(
        display_name="Play Framework",
        category="backend",
        aliases=["play framework", "playframework", "play"],
    ),
    Signature(
        display_name="Elm",
        category="frontend",
        aliases=["elm"],
    ),
]

FRAMEWORK_NAMES = [f.display_name for f in FRAMEWORK_SIGNATURES]
