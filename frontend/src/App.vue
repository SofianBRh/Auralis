<template>
    <div id="app">
      <h1>Bienvenue dans le PCAP Viewer</h1>
      <RequestList @request-sent="handleRequest" @response-received="handleResponse"/>
      <Dashboard/>
    </div>
  </template>
  
  <script>
  import RequestList from './components/RequestList.vue';
  import Dashboard from './components/Dashboard.vue';
  
  export default {
    name: 'App',
    components: {
      RequestList,
      Dashboard
    },
    methods: {
      handleRequest(request) {
        this.$root.$emit("request-sent", request);
      },
      handleResponse(response) {
        this.$root.$emit("response-received", response);
      }
    }
  }
  </script>
  
  <style scoped>
  #app {
    text-align: center;
    font-family: Arial, sans-serif;
  }
  
  h1 {
    color: #4CAF50;
  }
  </style>  