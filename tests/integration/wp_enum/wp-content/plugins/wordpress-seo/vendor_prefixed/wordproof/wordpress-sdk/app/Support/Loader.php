<?php

namespace YoastSEO_Vendor\WordProof\SDK\Support;

class Loader
{
    protected $actions;
    protected $filters;
    public function __construct()
    {
        $this->actions = [];
        $this->filters = [];
    }
    /**
     * @param string $hook The name of the WordPress action that is being registered.
     * @param object $component A reference to the instance of the object on which the action is defined.
     * @param string $callback The name of the function definition on the $component.
     * @param int $priority Optional. The priority at which the function should be fired. Default is 10.
     * @param int $accepted_args Optional. The number of arguments that should be passed to the $callback. Default is 1.
     */
    public function addAction($hook, $component, $callback, $priority = 10, $accepted_args = 1)
    {
        $this->actions = $this->add($this->actions, $hook, $component, $callback, $priority, $accepted_args);
    }
    /**
     * @param string $hook The name of the WordPress filter that is being registered.
     * @param object $component A reference to the instance of the object on which the filter is defined.
     * @param string $callback The name of the function definition on the $component.
     * @param int $priority Optional. The priority at which the function should be fired. Default is 10.
     * @param int $accepted_args Optional. The number of arguments that should be passed to the $callback. Default is 1
     */
    public function addFilter($hook, $component, $callback, $priority = 10, $accepted_args = 1)
    {
        $this->filters = $this->add($this->filters, $hook, $component, $callback, $priority, $accepted_args);
    }
    public function run()
    {
        foreach ($this->filters as $hook) {
            \add_filter($hook['hook'], [$hook['component'], $hook['callback']], $hook['priority'], $hook['accepted_args']);
        }
        foreach ($this->actions as $hook) {
            \add_action($hook['hook'], [$hook['component'], $hook['callback']], $hook['priority'], $hook['accepted_args']);
        }
    }
    private function add($hooks, $hook, $component, $callback, $priority, $accepted_args)
    {
        $hooks[] = ['hook' => $hook, 'component' => $component, 'callback' => $callback, 'priority' => $priority, 'accepted_args' => $accepted_args];
        return $hooks;
    }
}
